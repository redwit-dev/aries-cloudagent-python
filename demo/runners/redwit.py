import asyncio
import json
import logging
import os
import sys
import time
# for uid generation
import uuid

from aiohttp import (
    web,
    ClientError,
    ClientSession
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_json,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

# TODO: suggested on 210905
EXPIRATION_PERIOD_SEC = 40    # 100 seconds expiration for test

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class RedwitAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Redwit",
            no_auto=no_auto,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    # overrided on agent_container.py
    async def handle_issue_credential_v2_0(self, message):
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        connection_id = message['connection_id']    # TODO: check if this is correct or opposite side connection id is correct
        log_msg("Debug: connection id: "+connection_id)
        self.cred_ex_to_token[cred_ex_id] = self.connection_owner[connection_id]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            log_msg("Debug: Assertion:")
            log_msg(self.cred_ex_to_token[cred_ex_id] == self.subagent['wallet']['token'])
            log_status("#17 Issue credential to X")
            # issue credential based on offer preview in cred ex record
            headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
            await self.agency_admin_POST(
                f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                headers=headers
            )
        elif state == "offer-received":
            log_msg("Debug: Assertion:")
            log_msg(self.cred_ex_to_token[cred_ex_id] != self.subagent['wallet']['token'])
            log_status("#15 After receiving credential offer, send credential request")

            self.cred_waitings[cred_ex_id] = message['by_format']['cred_offer']['indy']['nonce']

            if message["by_format"]["cred_offer"].get("indy"):
                headers = self._attach_token_headers({}, self.cred_ex_to_token[cred_ex_id])
                await self.agency_admin_POST(f"/issue-credential-2.0/records/{cred_ex_id}/send-request", headers=headers)
        elif state == "done":
            pass
            # Logic moved to detail record specific handler

    # overrided on agent_container.py
    async def handle_issue_credential_v2_0_indy(self, message):
        log_msg("Debug: handle_issue_credential_v2_0_indy.")
        log_msg("Debug: cred_ex_id: "+message["cred_ex_id"])
        cred_ex_id = message["cred_ex_id"]

        rev_reg_id = message.get("rev_reg_id")
        cred_rev_id = message.get("cred_rev_id")
        cred_id_stored = message.get("cred_id_stored")

        if cred_id_stored:
            cred_id = message["cred_id_stored"]
            log_msg("Debug: Assertion:")
            log_msg(self.cred_ex_to_token[cred_ex_id] != self.subagent['wallet']['token'])
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            headers = self._attach_token_headers({}, self.cred_ex_to_token[cred_ex_id])
            log_msg(self.cred_ex_to_token[cred_ex_id])
            cred = await self.agency_admin_GET(f"/credential/{cred_id}", headers=headers)
            log_json(cred, label="Credential details:")
            self.log("credential_id", cred_id)
            self.log("cred_def_id", cred["cred_def_id"])
            self.log("schema_id", cred["schema_id"])
            # track last successfully received credential
            self.last_credential_received = cred

            cred_offer_nonce = self.cred_waitings[cred_ex_id]
            self.cred_nonce_waitings[cred_offer_nonce] = cred
            del self.cred_waitings[cred_ex_id]

        if rev_reg_id and cred_rev_id:
            self.log(f"Revocation registry ID: {rev_reg_id}")
            self.log(f"Credential revocation ID: {cred_rev_id}")

    # overrided on agent_container.py
    async def handle_present_proof_v2_0(self, message):
        log_msg("Debug: handle_present_proof_v2_0 called.")

        state = message["state"]
        pres_ex_id = message["pres_ex_id"]

        connection_id = message['connection_id']    # TODO: check if this is correct or opposite side connection id is correct
        log_msg("Debug: connection id: "+connection_id)
        self.pres_ex_to_token[pres_ex_id] = self.connection_owner[connection_id]

        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "request-received":
            log_msg("Debug: Assertion:")
            log_msg(self.pres_ex_to_token[pres_ex_id] != self.subagent['wallet']['token'])
            log_msg("Debug: token: "+self.pres_ex_to_token[pres_ex_id])
            # prover role
            log_status(
                "#24 Query for credentials in the wallet that satisfy the proof request"
            )
            pres_request_indy = message["by_format"].get("pres_request", {}).get("indy")
            pres_request_dif = message["by_format"].get("pres_request", {}).get("dif")

            if pres_request_indy:
                # include self-attested attributes (not included in credentials)
                creds_by_reft = {}
                revealed = {}
                self_attested = {}
                predicates = {}

                try:
                    # select credentials to provide for the proof
                    headers = self._attach_token_headers({}, self.pres_ex_to_token[pres_ex_id])
                    creds = await self.agency_admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials",
                        headers=headers
                    )
                    if creds:
                        if "timestamp" in creds[0]["cred_info"]["attrs"]:
                            sorted_creds = sorted(
                                creds,
                                key=lambda c: int(c["cred_info"]["attrs"]["timestamp"]),
                                reverse=True,
                            )
                        else:
                            sorted_creds = creds
                        for row in sorted_creds:
                            for referent in row["presentation_referents"]:
                                if referent not in creds_by_reft:
                                    creds_by_reft[referent] = row

                    for referent in pres_request_indy["requested_attributes"]:
                        if referent in creds_by_reft:
                            revealed[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ],
                                "revealed": True,
                            }
                        else:
                            self_attested[referent] = "my self-attested value"

                    for referent in pres_request_indy["requested_predicates"]:
                        if referent in creds_by_reft:
                            predicates[referent] = {
                                "cred_id": creds_by_reft[referent]["cred_info"][
                                    "referent"
                                ]
                            }

                    log_status("#25 Generate the proof")
                    request = {
                        "indy": {
                            "requested_predicates": predicates,
                            "requested_attributes": revealed,
                            "self_attested_attributes": self_attested,
                        }
                    }
                except ClientError:
                    pass

            elif pres_request_dif:
                try:
                    # select credentials to provide for the proof
                    headers = self._attach_token_headers({}, self.pres_ex_to_token[pres_ex_id])
                    creds = await self.agency_admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials",
                        headers=headers
                    )
                    if creds and 0 < len(creds):
                        creds = sorted(
                            creds,
                            key=lambda c: c["issuanceDate"],
                            reverse=True,
                        )
                        record_id = creds[0]["record_id"]
                    else:
                        record_id = None

                    log_status("#25 Generate the proof")
                    request = {
                        "dif": {},
                    }
                    # specify the record id for each input_descriptor id:
                    request["dif"]["record_ids"] = {}
                    for input_descriptor in pres_request_dif["presentation_definition"][
                        "input_descriptors"
                    ]:
                        request["dif"]["record_ids"][input_descriptor["id"]] = [
                            record_id,
                        ]
                    log_msg("presenting ld-presentation:", request)

                    # NOTE that the holder/prover can also/or specify constraints by including the whole proof request
                    # and constraining the presented credentials by adding filters, for example:
                    #
                    # request = {
                    #     "dif": pres_request_dif,
                    # }
                    # request["dif"]["presentation_definition"]["input_descriptors"]["constraints"]["fields"].append(
                    #      {
                    #          "path": [
                    #              "$.id"
                    #          ],
                    #          "purpose": "Specify the id of the credential to present",
                    #          "filter": {
                    #              "const": "https://credential.example.com/residents/1234567890"
                    #          }
                    #      }
                    # )
                    #
                    # (NOTE the above assumes the credential contains an "id", which is an optional field)

                except ClientError:
                    pass

            else:
                raise Exception("Invalid presentation request received")

            log_status("#26 Send the proof to X: " + json.dumps(request))
            headers = self._attach_token_headers({}, self.pres_ex_to_token[pres_ex_id])
            await self.agency_admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                request,
                headers=headers
            )

        elif state == "presentation-received":
            log_msg("Debug: Assertion:")
            log_msg(self.pres_ex_to_token[pres_ex_id] == self.subagent['wallet']['token'])
            # verifier role
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            headers = self._attach_token_headers({}, self.pres_ex_to_token[pres_ex_id])
            proof = await self.agency_admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation",
                headers=headers
            )
            self.last_proof_received = proof

            pres_waiting_result = {}
            if proof["verified"] != "true":
                pres_waiting_result["result"] = False
                self.pres_waitings[pres_ex_id] = pres_waiting_result
                self.log("Proof =", False)
                return

            attr_groups = message["by_format"]["pres"]["indy"]["requested_proof"]["revealed_attr_groups"]
            if "0_identification_uuid" in attr_groups:
                timelimit = attr_groups["0_identification_uuid"]["values"]["expirationDate"]["raw"]
                if int(timelimit) < int(time.time()):
                    pres_waiting_result["result"] = False
                    self.pres_waitings[pres_ex_id] = pres_waiting_result
                    self.log("Proof =", False)
                    return
                uid = attr_groups["0_identification_uuid"]["values"]["uid"]["raw"]
                pres_waiting_result["uid"] = uid
            elif "0_pass_uuid" in attr_groups:
                timelimit = attr_groups["0_pass_uuid"]["values"]["end-date"]["raw"]
                if int(timelimit) < int(time.time()):
                    pres_waiting_result["result"] = False
                    self.pres_waitings[pres_ex_id] = pres_waiting_result
                    self.log("Proof =", False)
                    return
            else:
                pres_waiting_result["result"] = False
                self.pres_waitings[pres_ex_id] = pres_waiting_result
                self.log("Proof =", False)
                return
            pres_waiting_result["result"] = True
            self.pres_waitings[pres_ex_id] = pres_waiting_result
            self.log("Proof =", True)

    def _attach_token_headers(self, headers, token):
        headers["Authorization"] = (
            "Bearer " + token
        )
        return headers

    def _get_token_no(self, token):
        if token in self.tokenpool:
            return self.tokenpool[token]
        else:
            self.tokenpool[token] = len(self.tokenpool)
            return self.tokenpool[token]
    async def _get_connection(self, from_token, to_token):
        from_token_no = self._get_token_no(from_token)
        to_token_no = self._get_token_no(to_token)

        # TODO in future, optimize the structure when the user size is very large.
        if from_token_no in self.connections:
            if to_token_no in self.connections[from_token_no]:
                return self.connections[from_token_no][to_token_no]
        else:
            self.connections[from_token_no] = {}
        
        data = {}
        headers = self._attach_token_headers({}, from_token)
        res = await self.agency_admin_POST("/connections/create-invitation", data=data, headers=headers)
        from_connection = res["connection_id"]
        data = res["invitation"]
        headers = self._attach_token_headers({}, to_token)
        res = await self.agency_admin_POST("/connections/receive-invitation", data=data, headers=headers)
        to_connection = res["connection_id"]
        if not (to_token_no in self.connections):
            self.connections[to_token_no] = {}
        self.connections[from_token_no][to_token_no] = from_connection
        self.connections[to_token_no][from_token_no] = to_connection
        self.connection_owner[from_connection] = from_token
        self.connection_owner[to_connection] = to_token
        return from_connection

    async def _get_wallet_id(self, name):
        res = await self.agency_admin_GET("/multitenancy/wallets");
        if not ("results" in res):
            return None
        for x in res["results"]:
            if x["settings"]["wallet.name"] == name:
                return x["wallet_id"]
        return None

    async def _get_token(self, wallet_id, key):
        data = {"wallet_key": key}
        res = await self.agency_admin_POST("/multitenancy/wallet/"+wallet_id+"/token", data=data)
        return res["token"]
        
    async def _create_did(self, token, did_type):
        data = {}
        if (did_type == "sov"):
            data = {"method": "sov", "options": {"key_type": "ed25519"}}
        elif (did_type == "key"):
            data = {"method": "key", "options": {"key_type": "bls12381g2"}}
        headers = self._attach_token_headers({}, token)
        did_key = await self.agency_admin_POST("/wallet/did/create", data=data, headers=headers)
        return did_key

    async def _get_did(self, token, did_type):
        headers = self._attach_token_headers({}, token)
        dids = await self.agency_admin_GET("/wallet/did", headers=headers)
        if "results" in dids:
            for x in dids["results"]:
                if (did_type == "sov" and x["did"][0:8] == "did:sov:"):
                    return x["did"]
                if (did_type == "key" and x["did"][0:8] == "did:key:"):
                    return x["did"]
        return None

    async def setup_subagent_did(self):
        self.connections = {}
        self.connection_owner = {}
        self.cred_ex_to_token = {}
        self.pres_ex_to_token = {}
        self.tokenpool = {}
        self.subagent['sov'] = await self._create_did(self.subagent['wallet']['token'], "sov")
        self.subagent['key'] = await self._create_did(self.subagent['wallet']['token'], "key")
        return

    # TODO: check revocation is required or not
    async def setup_schemas(self):
        self.schemas = {}

        # identification schema
        attrs = [
        'uid',
        'app-id',
        'internal',
        'group',
        'military-id',
        'name-ko',
        'name-en',
        'resident-number-head',
        'resident-number-tail',
        'branch',
        'blood-type',
        'grade',
        'issuer',
        'department',
        'phone-additional',
        'phone-mobile',
        # TODO: suggested on 210905
        'expirationDate'
        ]
        # which returns schema_id, credential_definition_id
        s = await self.register_schema_and_creddef(
                "id_schema",
                "1.0.0",
                attrs
            )
        self.schemas['identification'] = {}
        self.schemas['identification']['schema_id'] = s[0]
        self.schemas['identification']['creddef_id'] = s[1]

        # pass schema
        attrs = [
        'uid',
        'entry-type',
        'issue-date',
        'honor-id',
        'vehicles',
        'additional-areas',
        'start-date',
        'end-date',
        'escort-department',
        'escort-grade',
        'escort-name',
        'escort-phone-additional',
        'escort-phone-mobile',
        'objective'
        ]
        # which returns schema_id, credential_definition_id
        s = await self.register_schema_and_creddef(
                "pass_schema",
                "1.0.0",
                attrs
            )
        self.schemas['pass'] = {}
        self.schemas['pass']['schema_id'] = s[0]
        self.schemas['pass']['creddef_id'] = s[1]


    async def user_registration(self, name, key):
        data = {
        "key_management_mode": "managed",
        "wallet_dispatch_type": "default",
        "wallet_name": name,
        "wallet_key": key,
        "wallet_type": "indy"
        }

        # check the name does not exists
        prev_user_wallet = await self._get_wallet_id(name)
        if prev_user_wallet != None:
            log_msg("Debug: The user name "+name+" is already used.")
            return False
        # u = await self.agency_admin_GET("/multitenancy/wallets?wallet_name="+name)
        # err = not ('results' in u.keys())
        # if (err):
        #     log_msg("Debug: REST API does not return result.")
        #     return False
        # u = u['results']
        # if (len(u) > 0):
        #     log_msg("Debug: The user name "+name+" is already used.")
        #     return False

        # register user
        registration = await self.agency_admin_POST("/multitenancy/wallet", data=data)

        # register user did(sov)
        await self._create_did(registration['token'], "sov")
        # register user did(key)
        await self._create_did(registration['token'], "key")

        # debug
        # get wallet id
        debug_wallet_id = await self._get_wallet_id(name)
        log_msg("Debug: debug wallet id: "+debug_wallet_id)
        # get token
        debug_token = await self._get_token(debug_wallet_id, key)
        log_msg("Debug: debug_token: "+debug_token)
        # get did key
        debug_did_key = await self._get_did(debug_token, "key")
        log_msg("Debug: debug_did_key: "+debug_did_key)

        connection = await self._get_connection(self.subagent['wallet']['token'], debug_token)
        log_msg("Debug: "+self.subagent['wallet']['token'])
        log_msg("Debug: "+debug_token)
        log_msg("Debug: "+connection)
        return debug_did_key

    async def user_issue_identification(self, name, key, data):
        # get user wallet
        user_wallet_id = await self._get_wallet_id(name)
        if user_wallet_id == None:
            log_msg("Debug: user not exists")
            return None
        user_wallet_token = await self._get_token(user_wallet_id, key)
        if user_wallet_token == None:
            # TODO: catch error
            return None

        # get user's did key
        user_did_key = await self._get_did(user_wallet_token, "key")
        log_msg("Debug[user_did_key]: "+user_did_key)
        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)
        log_msg("Debug[token]: "+self.subagent['wallet']['token'])
        log_msg("Debug[wallet_token]: "+user_wallet_token)
        log_msg("Debug[connection_id]: "+connection_id)

        # uid generation
        if "uid" in data:
            # error
            log_msg("Debug: data should not contain uid")
            return None
        uid = 'TODO: random uuid format required'
        data['uid'] = str(uuid.uuid1()) # TODO: is the uuid1 makes collision?

        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v}
                    for (n, v) in data.items()
            ],
        }
        log_msg("Debug[creddef_id]: "+self.schemas['identification']['creddef_id'])
        offer_request = {
            "connection_id": connection_id,
            "comment": f"Offer on cred def id {self.schemas['identification']['creddef_id']}",
            "auto_remove": False,
            "credential_preview": cred_preview,
            "filter": {
                "indy": {
                    "cred_def_id": self.schemas['identification']['creddef_id']
                }
            },
            "trace": False,
        }
        headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
        res = await self.agency_admin_POST("/issue-credential-2.0/send-offer", data=offer_request, headers=headers)
        
        # busy polling
        cred_offer_nonce = res['by_format']['cred_offer']['indy']['nonce']
        while(not (cred_offer_nonce in self.cred_nonce_waitings)):
            await asyncio.sleep(1)
        cred = self.cred_nonce_waitings[cred_offer_nonce]
        del self.cred_nonce_waitings[cred_offer_nonce]
        rtn = json.dumps(cred)

        return rtn

    # TODO
    async def user_issue_pass(self, name, key, data):
        # get user wallet
        user_wallet_id = await self._get_wallet_id(name)
        if user_wallet_id == None:
            log_msg("Debug: user not exists")
            return None
        user_wallet_token = await self._get_token(user_wallet_id, key)
        if user_wallet_token == None:
            # TODO: catch error
            return None

        # get user's did key
        user_did_key = await self._get_did(user_wallet_token, "key")
        log_msg("Debug[user_did_key]: "+user_did_key)
        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)
        log_msg("Debug[token]: "+self.subagent['wallet']['token'])
        log_msg("Debug[wallet_token]: "+user_wallet_token)
        log_msg("Debug[connection_id]: "+connection_id)

        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v}
                    for (n, v) in data.items()
            ],
        }
        log_msg("Debug[creddef_id]: "+self.schemas['pass']['creddef_id'])
        offer_request = {
            "connection_id": connection_id,
            "comment": f"Offer on cred def id {self.schemas['pass']['creddef_id']}",
            "auto_remove": False,
            "credential_preview": cred_preview,
            "filter": {
                "indy": {
                    "cred_def_id": self.schemas['pass']['creddef_id']
                }
            },
            "trace": False,
        }
        headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
        res = await self.agency_admin_POST("/issue-credential-2.0/send-offer", data=offer_request, headers=headers)
        
        # busy polling
        cred_offer_nonce = res['by_format']['cred_offer']['indy']['nonce']
        while(not (cred_offer_nonce in self.cred_nonce_waitings)):
            await asyncio.sleep(1)
        cred = self.cred_nonce_waitings[cred_offer_nonce]
        del self.cred_nonce_waitings[cred_offer_nonce]
        rtn = json.dumps(cred)

        return rtn

    async def user_check_identification(self, name, key, uid=None):
        # get user wallet
        user_wallet_id = await self._get_wallet_id(name)
        if user_wallet_id == None:
            log_msg("Debug: user not exists")
            return {"result": False}
        user_wallet_token = await self._get_token(user_wallet_id, key)
        if user_wallet_token == None:
            # TODO: catch error
            return {"result": False}

        # get user's did key
        user_did_key = await self._get_did(user_wallet_token, "key")

        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)

        restriction = {}
        restriction["schema_name"] = "id_schema"
        if uid != None:
            restriction["attr::uid::value"] = uid
        indy_proof_request = {
            "name": "Proof of Identification",
            "version": "1.0",
            "requested_attributes": {
                f"0_identification_uuid": {
                    "names": [
                        'uid',
                        'app-id',
                        'internal',
                        'group',
                        'military-id',
                        'name-ko',
                        'name-en',
                        'resident-number-head',
                        'resident-number-tail',
                        'branch',
                        'blood-type',
                        'grade',
                        'issuer',
                        'department',
                        'phone-additional',
                        'phone-mobile',
                        'expirationDate'
                    ],
                    "restrictions": [restriction]
                }
            },
            "requested_predicates": {},
        }
        proof_request_web_request = {
            "connection_id": connection_id,
            "presentation_request": {"indy": indy_proof_request},
            "trace": False,
        }
        headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
        res = await self.agency_admin_POST(
            "/present-proof-2.0/send-request",
            proof_request_web_request,
            headers=headers
        )

        # busy polling
        pres_request_nonce = res['by_format']['pres_request']['indy']['nonce']

        pres_ex_id = res['pres_ex_id']
        while(not (pres_ex_id in self.pres_waitings)):
            await asyncio.sleep(1)
        proof_check_result = self.pres_waitings[pres_ex_id]

        return proof_check_result

    # TODO: uid check implementation
    async def user_check_pass(self, name, key, uid, entry_type=None):
        # TODO: choose design: add id check in here, or always call both id_check and pass_check
        id_check = await self.user_check_identification(name, key, uid)
        if not id_check['result']:
            return {"result":False}

        # get user wallet
        user_wallet_id = await self._get_wallet_id(name)
        if user_wallet_id == None:
            log_msg("Debug: user not exists")
            return {"result": False}
        user_wallet_token = await self._get_token(user_wallet_id, key)
        if user_wallet_token == None:
            # TODO: catch error
            return {"result": False}

        # get user's did key
        user_did_key = await self._get_did(user_wallet_token, "key")

        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)


        restriction = {}
        restriction["schema_name"] = "pass_schema"
        restriction["attr::uid::value"] = uid
        if entry_type != None:
            restriction["attr::entry-type::value"] = entry_type
        indy_proof_request = {
            "name": "Proof of Pass",
            "version": "1.0",
            "requested_attributes": {
                f"0_pass_uuid": {
                    "names": [
                        'uid',
                        'entry-type',
                        'issue-date',
                        'honor-id',
                        'vehicles',
                        'additional-areas',
                        'start-date',
                        'end-date',
                        'escort-department',
                        'escort-grade',
                        'escort-name',
                        'escort-phone-additional',
                        'escort-phone-mobile',
                        'objective'
                    ],
                    "restrictions": [restriction]
                }
            },
            "requested_predicates": {},
        }
        proof_request_web_request = {
            "connection_id": connection_id,
            "presentation_request": {"indy": indy_proof_request},
            "trace": False,
        }
        headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
        res = await self.agency_admin_POST(
            "/present-proof-2.0/send-request",
            proof_request_web_request,
            headers=headers
        )

        # busy polling
        pres_request_nonce = res['by_format']['pres_request']['indy']['nonce']

        pres_ex_id = res['pres_ex_id']
        while(not (pres_ex_id in self.pres_waitings)):
            await asyncio.sleep(1)
        proof_check_result = self.pres_waitings[pres_ex_id]

        return proof_check_result

    async def _handle_webfront_get_default(self, request):
        resp_obj = {'status': 'success'}
        return web.Response(text=json.dumps(resp_obj))
    async def _handle_webfront_post_default(self, request):
        resp_obj = {'status': 'success'}
        return web.Response(text=json.dumps(resp_obj))

    async def _handle_register_user(self, request: web.BaseRequest):
        body = await request.json()
        log_msg( 'json')
        log_json( body )
        name = body.get("name")
        key = body.get("key")
        try:
            did = await self.user_registration( name, key )
            resp_obj = { 'did' : did, 'status': 'success' }
            return web.json_response(resp_obj)
        except ClientError:
            log_msg( ClientError )
            resp_obj = { 'status': 'failed', 'msg': ClientError }
            return web.json_response(resp_obj)

    async def _handle_issue_identification(self, request: web.BaseRequest):
        body = await request.json()
        name = body.get("name")
        key = body.get("key")
        log_msg( 'UserInfo: ' + name + key )
        del body["name"]
        del body["key"]
        try:
            res = await self.user_issue_identification( name, key , body)
            log_msg( res )
            resp_obj = { 'vc' : res, 'status': 'success' }
            return web.json_response(resp_obj)
        except ClientError:
            log_msg( ClientError )
            resp_obj = { 'status': 'failed', 'msg': ClientError }
            return web.json_response(resp_obj)

    async def _handle_check_identification(self, request: web.BaseRequest):
        body = await request.json()
        name = body.get("name")
        key = body.get("key")
        uid = body.get("uid")
        log_msg( 'UserInfo: ' + name + key + uid)
        del body["name"]
        del body["key"]
        try:
            res = await self.user_check_identification( name, key, uid)
            log_msg( res )
            resp_obj = { 'vp' : res, 'status': 'success' }
            return web.json_response(resp_obj)
        except ClientError:
            log_msg( ClientError )
            resp_obj = { 'status': 'failed', 'msg': ClientError }
            return web.json_response(resp_obj)

    async def init_webfront(self, webfront_port):
        self.webfront_port = webfront_port
        webfront = web.Application()

        # TODO: implement App REST front
        webfront.add_routes([
            web.get('/', self._handle_webfront_get_default),
            web.post('/', self._handle_webfront_post_default),
            web.post('/register', self._handle_register_user),
            web.post('/issue/identification', self._handle_issue_identification),
            web.post('/check/identification', self._handle_check_identification),
        ])

        runner = web.AppRunner(webfront)
        await runner.setup()
        self.webfront_site = web.TCPSite(runner, "0.0.0.0", webfront_port)
        await self.webfront_site.start()

async def main(args):
    redwit_agent = await create_agent_with_args(args, ident="redwit")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {redwit_agent.wallet_type})"
                if redwit_agent.wallet_type
                else ""
            )
        )
        agent = RedwitAgent(
            "redwit.agent",
            redwit_agent.start_port,
            redwit_agent.start_port + 1,
            genesis_data=redwit_agent.genesis_txns,
            no_auto=redwit_agent.no_auto,
            tails_server_base_url=redwit_agent.tails_server_base_url,
            timing=redwit_agent.show_timing,
            multitenant=redwit_agent.multitenant,
            mediation=redwit_agent.mediation,
            wallet_type=redwit_agent.wallet_type,
            seed=redwit_agent.seed,
            subagent_wallet_key=redwit_agent.subagent_wallet_key,
        )

        redwit_agent.public_did = True
        await redwit_agent.initialize(the_agent=agent)
        await agent.setup_subagent_did()
        await agent.setup_schemas()

        agent.cred_nonce_waitings = {}
        agent.cred_waitings = {}
        agent.pres_waitings = {}

        await agent.init_webfront(8080)


        # test local server
        async with ClientSession() as session:
            url='http://localhost:8080/register'
            payload = { 'name' : 'any00', 'key': 'pass1234'}
            headers = {'content-type': 'application/json'}
            async with session.post( url, json=payload, headers=headers ) as resp:
                log_msg(resp.status)
                log_msg(await resp.text())
        await asyncio.sleep(1)
        cred_id = ""
        async with ClientSession() as session:
            url='http://localhost:8080/issue/identification'
            # TODO : token based authentication
            SAMPLE_ID_DATA = {
                'name' : 'any00', 'key': 'pass1234', # for authentication
                'app-id': 'zyxwvu...',
                'internal': 'true',
                'group': '1-1',
                'military-id': '00-0000',
                'name-ko': '성춘향',
                'name-en': 'Seong Chun Hyang',
                'resident-number-head': '981212',
                'resident-number-tail': '1234567',
                'branch': 'ARTILLERY',
                'blood-type': 'O',
                'grade': 'ARMY-O-3',
                'issuer': '육군사관학교',
                'department': 'A',
                'phone-additional': '02-123-4567',
                'phone-mobile': '010-2222-2222',
                # TODO: suggested on 210905
                'expirationDate': str(int(time.time()) + EXPIRATION_PERIOD_SEC)
                }
            headers = {'content-type': 'application/json'}
            async with session.post( url, json=SAMPLE_ID_DATA, headers=headers ) as resp:
                log_msg(resp.status)
                resp_str = await resp.text()
                resp_obj = json.loads(resp_str)['vc']
                uid = json.loads(resp_obj)['attrs']['uid']
                log_msg( '*************Verifiable Credential***********' )
                log_msg( resp_str )
        async with ClientSession() as session:
            url='http://localhost:8080/check/identification'
            # TODO : token based authentication
            json_data = {
                'name' : 'any00', 'key': 'pass1234', 'uid': uid, # for authentication
                }
            headers = {'content-type': 'application/json'}
            async with session.post( url, json=json_data, headers=headers ) as resp:
                log_msg(resp.status)
                log_msg(await resp.text())

        await agent.user_registration('any01', '1234')
        await asyncio.sleep(1)
        SAMPLE_ID_DATA = {
            'app-id': 'zyxwvu...',
            'internal': 'true',
            'group': '1-1',
            'military-id': '00-0000',
            'name-ko': '성춘향',
            'name-en': 'Seong Chun Hyang',
            'resident-number-head': '981212',
            'resident-number-tail': '1234567',
            'branch': 'ARTILLERY',
            'blood-type': 'O',
            'grade': 'ARMY-O-3',
            'issuer': '육군사관학교',
            'department': 'A',
            'phone-additional': '02-123-4567',
            'phone-mobile': '010-2222-2222',
            # TODO: suggested on 210905
            'expirationDate': str(int(time.time()) + EXPIRATION_PERIOD_SEC)
        }
        res = await agent.user_issue_identification('any01', '1234', SAMPLE_ID_DATA)
        uid1 = json.loads(res)['attrs']['uid']
        SAMPLE_ID_DATA = {
            'app-id': 'zyxwvu...',
            'internal': 'true',
            'group': '1-1',
            'military-id': '00-0000',
            'name-ko': '성춘향',
            'name-en': 'Seong Chun Hyang',
            'resident-number-head': '981212',
            'resident-number-tail': '1234567',
            'branch': 'ARTILLERY',
            'blood-type': 'O',
            'grade': 'ARMY-O-3',
            'issuer': '육군사관학교',
            'department': 'A',
            'phone-additional': '02-123-4567',
            'phone-mobile': '010-2222-2222',
            # TODO: suggested on 210905
            'expirationDate': str(int(time.time()) + EXPIRATION_PERIOD_SEC)
        }
        res = await agent.user_issue_identification('any01', '1234', SAMPLE_ID_DATA)
        uid2 = json.loads(res)['attrs']['uid']
        SAMPLE_PASS_DATA = {
            'uid': uid1,
            'entry-type': '1-1',
            'issue-date': '2021-08-23 23:45:01',
            'honor-id': '',
            'vehicles': '',
            'additional-areas': '',
            'start-date': str(int(time.time())),
            'end-date': str(int(time.time()) + EXPIRATION_PERIOD_SEC),
            'escort-department': '',
            'escort-grade': '',
            'escort-name': '',
            'escort-phone-additional': '',
            'escort-phone-mobile': '',
            'objective': ''
            }
        await agent.user_issue_pass('any01', '1234', SAMPLE_PASS_DATA)
        SAMPLE_PASS_DATA = {
            'uid': uid2,
            'entry-type': '1-2',
            'issue-date': '2021-08-23 23:45:01',
            'honor-id': '',
            'vehicles': '',
            'additional-areas': '',
            'start-date': str(int(time.time())),
            'end-date': str(int(time.time()) + EXPIRATION_PERIOD_SEC),
            'escort-department': '',
            'escort-grade': '',
            'escort-name': '',
            'escort-phone-additional': '',
            'escort-phone-mobile': '',
            'objective': ''
            }
        await agent.user_issue_pass('any01', '1234', SAMPLE_PASS_DATA)
        pass_check = await agent.user_check_pass('any01', '1234', uid1, entry_type='1-2')
        if pass_check['result']:
            log_msg("PASS CHECK SUCCESS, which means bad")
        else:
            log_msg("PASS CHECK FAIL, which means good")
        pass_check = await agent.user_check_pass('any01', '1234', uid1, entry_type='1-1')
        if pass_check['result']:
            log_msg("PASS CHECK SUCCESS, which means good")
        else:
            log_msg("PASS CHECK FAIL, which means bad")
        pass_check = await agent.user_check_pass('any01', '1234', uid2, entry_type='1-2')
        if pass_check['result']:
            log_msg("PASS CHECK SUCCESS, which means good")
        else:
            log_msg("PASS CHECK FAIL, which means bad")

        options = ""
        options += "    (W) DEBUG user_registration\n"
        options += "    (I) DEBUG user_issue_identification\n"
        options += "    (C) DEBUG user_check_identification\n"
        options += "    (P) DEBUG user_issue_pass\n"
        options += "    (E) DEBUG user_check_pass\n"
        options += "    (X) Exit?\n "
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break
            elif option in "wW":
                await agent.user_registration('any00', 'pass1234')
            elif option in "iI":

                # SAMPLE ID DATA
                SAMPLE_ID_DATA = {
                'app-id': 'zyxwvu...',
                'internal': 'true',
                'group': '1-1',
                'military-id': '00-0000',
                'name-ko': '성춘향',
                'name-en': 'Seong Chun Hyang',
                'resident-number-head': '981212',
                'resident-number-tail': '1234567',
                'branch': 'ARTILLERY',
                'blood-type': 'O',
                'grade': 'ARMY-O-3',
                'issuer': '육군사관학교',
                'department': 'A',
                'phone-additional': '02-123-4567',
                'phone-mobile': '010-2222-2222',
                # TODO: suggested on 210905
                'expirationDate': str(int(time.time()) + EXPIRATION_PERIOD_SEC)
                }

                await agent.user_issue_identification('any00', 'pass1234', SAMPLE_ID_DATA)
            elif option in "pP":

                id_check = await agent.user_check_identification('any00', 'pass1234')
                if id_check['result']:
                    # SAMPLE ID DATA
                    SAMPLE_PASS_DATA = {
                    'uid': id_check['uid'],
                    'entry-type': '1-1',
                    'issue-date': '2021-08-23 23:45:01',
                    'honor-id': '',
                    'vehicles': '',
                    'additional-areas': '',
                    'start-date': str(int(time.time())),
                    'end-date': str(int(time.time()) + EXPIRATION_PERIOD_SEC),
                    'escort-department': '',
                    'escort-grade': '',
                    'escort-name': '',
                    'escort-phone-additional': '',
                    'escort-phone-mobile': '',
                    'objective': ''
                    }
                    await agent.user_issue_pass('any00', 'pass1234', SAMPLE_PASS_DATA)
            elif option in "cC":    # check identification
                id_check = await agent.user_check_identification('any00', 'pass1234')
                if id_check['result']:
                    log_msg("ID CHECK SUCCESS")
                else:
                    log_msg("ID CHECK FAIL")
            elif option in "eE":    # check pass
                pass_check = await agent.user_check_pass('any00', 'pass1234', 'TODO: random uuid format required')
                if pass_check['result']:
                    log_msg("PASS CHECK SUCCESS")
                else:
                    log_msg("PASS CHECK FAIL")

        if redwit_agent.show_timing:
            timing = await redwit_agent.agent.fetch_timing()
            if timing:
                for line in redwit_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await redwit_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="redwit", port=8000)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Redwit remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
