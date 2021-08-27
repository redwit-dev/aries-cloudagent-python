import asyncio
import json
import logging
import os
import sys
import time

from aiohttp import (
    web,
    ClientError,
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
        self.cred_ex_to_token[cred_ex_id] = self.connection_owner[connection_id]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state

        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            log_status("#17 Issue credential to X")
            # issue credential based on offer preview in cred ex record
            headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
            await self.agency_admin_POST(
                f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                headers=headers
            )
        elif state == "offer-received":
            log_status("#15 After receiving credential offer, send credential request")
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

        if rev_reg_id and cred_rev_id:
            self.log(f"Revocation registry ID: {rev_reg_id}")
            self.log(f"Credential revocation ID: {cred_rev_id}")

    # overrided on agent_container.py
    async def handle_issue_credential_v2_0_ld_proof(self, message):
        log_msg("Debug: handle_issue_credential_v2_0_ld_proof called.")
        log_msg(message)
        pass

    # overrided on agent_container.py
    async def handle_present_proof_v2_0(self, message):
        log_msg("Debug: handle_present_proof_v2_0 called.")
        log_msg(message)
        return

        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "request-received":
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
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
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
                    creds = await self.admin_GET(
                        f"/present-proof-2.0/records/{pres_ex_id}/credentials"
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
            await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/send-presentation",
                request,
            )

        elif state == "presentation-received":
            # verifier role
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof =", proof["verified"])
            self.last_proof_received = proof

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
        'phone-mobile'
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
        'entry-type',
        'issue-date',
        'honor-id',
        'vehicles',
        'additional-areas',
        'start-date',
        'end-date'
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
        return

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

        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)
        log_msg("Debug: "+self.subagent['wallet']['token'])
        log_msg("Debug: "+user_wallet_token)
        log_msg("Debug: "+connection_id)

        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v}
                    for (n, v) in data.items()
            ],
        }
        log_msg("Debug: "+self.schemas['identification']['creddef_id'])
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
        await self.agency_admin_POST("/issue-credential-2.0/send-offer", data=offer_request, headers=headers)
        return

    # TODO
    async def user_issue_pass(self, name, key):
        pass
        return

    # TODO
    async def user_check_identification(self, name, key, asf):
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

        # establish connection
        connection_id = await self._get_connection(self.subagent['wallet']['token'], user_wallet_token)

        attrs = [
        'resident-number-head',
        'resident-number-tail',
        'branch',
        'blood-type',
        'grade',
        'issuer',
        'department',
        'phone-additional',
        'phone-mobile'
        ]
        req_attrs = [
            {
                "name": "uid",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "internal",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "group",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "military-id",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "name-ko",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "name-en",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "resident-number-head",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "resident-number-tail",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "branch",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "blood-type",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "grade",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "issuer",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "department",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "phone-additional",
                "restrictions": [{"schema_name": "id_schema"}],
            },
            {
                "name": "phone-mobile",
                "restrictions": [{"schema_name": "id_schema"}],
            },
        ]
        indy_proof_request = {
            "name": "Proof of Identification",
            "version": "1.0",
            "requested_attributes": {
                f"0_{req_attr['name']}_uuid": req_attr
                for req_attr in req_attrs
            },
        }
        proof_request_web_request = {
            "connection_id": connection_id,
            "presentation_request": {"indy": indy_proof_request},
            "trace": False,
        }
        headers = self._attach_token_headers({}, self.subagent['wallet']['token'])
        await self.agency_admin_POST(
            "/present-proof-2.0/send-request",
            proof_request_web_request,
            headers=headers
        )

    # TODO
    async def user_check_pass(self, name, key, asf):
        pass
        return

    async def _handle_webfront_get_default(self, request):
        resp_obj = {'status': 'success'}
        return web.Response(text=json.dumps(resp_obj))
    async def _handle_webfront_post_default(self, request):
        resp_obj = {'status': 'success'}
        return web.Response(text=json.dumps(resp_obj))

    async def init_webfront(self, webfront_port):
        self.webfront_port = webfront_port
        webfront = web.Application()

        # TODO: implement App REST front
        webfront.add_routes([
            web.get('/', self._handle_webfront_get_default),
            web.post('/', self._handle_webfront_post_default),
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
        await agent.init_webfront(8080)

        options = ""
        options += "    (W) DEBUG user_registration\n"
        options += "    (I) DEBUG user_issue_identification\n"
        options += "    (C) DEBUG user_check_identification\n"
        options += "    (X) Exit?\n "
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break
            elif option in "wW":
                await agent.user_registration("SAMPLE_USER_NAME", "SAMPLE_USER_KEY")
            elif option in "iI":

                # SAMPLE ID DATA
                SAMPLE_ID_DATA = {
                'uid': 'zyxwvu...',
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
                'phone-mobile': '010-2222-2222'
                }

                await agent.user_issue_identification("SAMPLE_USER_NAME", "SAMPLE_USER_KEY", SAMPLE_ID_DATA)
            elif option in "pP":
                pass # TODO: implement
                # # SAMPLE ID DATA
                # SAMPLE_ID_DATA = {
                # 'uid': 'zyxwvu...',
                # 'entry-type': '',
                # 'issue-date': '',
                # 'honor-id': '',
                # 'vehicles': '',
                # 'additional-areas': '',
                # 'start-date': '',
                # 'end-date': '',
                # 'escort-department': '',
                # 'escort-grade': '',
                # 'escort-name': '',
                # 'escort-phone-additional': '',
                # 'escort-phone-mobile': '',
                # 'escort-objective': ''
                # }

                # await agent.user_check_identification("SAMPLE_USER_NAME", "SAMPLE_USER_KEY", "zyxwvu...")
                # await agent.user_issue_pass("SAMPLE_USER_NAME", "SAMPLE_USER_KEY", SAMPLE_ID_DATA)
            elif option in "cC":    # check identification
                pass # TODO: implement
                await agent.user_check_identification("SAMPLE_USER_NAME", "SAMPLE_USER_KEY", "SAMPLE_ID")
            elif option in "eE":    # check pass
                pass # TODO: implement
                await agent.user_check_pass("SAMPLE_USER_NAME", "SAMPLE_USER_KEY", "PASS VC 1")


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
