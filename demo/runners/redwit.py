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
    prompt,
    prompt_loop,
)

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

    def _attach_token_headers(self, headers, token):
        headers["Authorization"] = (
            "Bearer " + token
        )
        return headers

    async def _create_did_key(self, token):   
        data = {"method": "key", "options": {"key_type": "bls12381g2"}}
        headers = self._attach_token_headers({}, token)
        did_key = await self.agency_admin_POST("/wallet/did/create", data=data, headers=headers)
        log_msg(did_key) # debug
        return did_key

    async def setup_subagent_key(self):        
        self.subagent['key'] = await self._create_did_key(self.subagent['wallet']['token'])
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
        self.schemas['identification'] = s

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
        self.schemas['pass'] = s



    async def user_registeration(self, name, key):
        data = {
        "key_management_mode": "managed",
        "wallet_dispatch_type": "default",
        "wallet_name": name,
        "wallet_key": key,
        "wallet_type": "indy"
        }

        # check the name does not exists
        u = await self.agency_admin_GET("/multitenancy/wallets?wallet_name="+name)
        err = not ('results' in u.keys())
        if (err):
            log_msg("Debug: REST API does not return result.")
            return False
        u = u['results']
        if (len(u) > 0):
            log_msg("Debug: The user name "+name+" is already used.")
            return False

        # register user
        registration = await self.agency_admin_POST("/multitenancy/wallet", data=data)
        log_msg(registration['token']) # debug

        # register user did(key)
        await self._create_did_key(registration['token'])
        return

    async def user_issue_identification(self, name, key, data):

        if not self.schemas['identification']: # check tuple is empty
            self.user_registeration( name, key )
        else:
            log_msg( '[identification description]')
            log_msg( self.schemas['identification'] )
        cred_request = {
        "@type": "https://didcomm.org/issue-credential/2.0/propose-credential", # TODO: check this meaning
        "formats": [

        ]
        }

        cred_preview = {
        "@type": "https://didcomm.org/issue-credential/2.0/credential-preview", # TODO: check this meaning
        "attributes": [
        {"name": n, "value": v}
        for (n, v) in data.items()
        ],
        }

        offer_request = {
        "connection_id": self.connection_id,
        "comment": f"Offer on cred def id {self.schemas['identification'][1]}",
        "auto_remove": False,
        "credential_preview": cred_preview,
        "filter": {
            "indy": {"cred_def_id": self.schemas['identification'][1]}
        },
        "trace": False,
        }

        # get wallet id
        user = await self.agency_admin_GET("/multitenancy/wallets?wallet_name="+name)
        err = not ('results' in user.keys())
        if (err):
            log_msg("Debug: REST API does not return result.")
            return
        if (len(user['results']) != 1):
            log_msg("Debug: The results are move than one or empty.")
            return
        user_wallet_id = user['results'][0]['wallet_id']

        # get user token
        data = {
        'wallet_key': key
        }
        res = await self.agency_admin_POST("/multitenancy/wallet/"+user_wallet_id+"/token", data=data)
        user_wallet_token = res['token']

        # get user did(key)

        # get 


        return

    async def user_issue_pass(self, name, key):
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
        await agent.setup_subagent_key()
        await agent.setup_schemas()
        await agent.init_webfront(8080)

        options = ""
        options += "    (W) DEBUG user_registeration\n"
        options += "    (I) DEBUG user_issue_identification\n"
        options += "    (X) Exit?\n "
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "wW":
                await agent.user_registeration("SAMPLE_USER_NAME", "SAMPLE_USER_KEY")
            elif option in "iI":

                # SAMPLE ID DATA
                SAMPLE_ID_DATA = {
                'uid': 'zyxwvu...',
                'internal': True,
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
