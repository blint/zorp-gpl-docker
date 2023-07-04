from  Zorp.Core import  *
from  Zorp.Proxy import  *
from  Zorp.Http import  *
from  Zorp.Plug import  *
from  Zorp.Encryption import *
from  Zorp.Auth import  *
from  Zorp.AuthDB import *

Zorp.firewall_name = 'zorp@docker'
config.options.kzorp_enabled = FALSE

class ConnnectHttpsProxy(PlugProxy):
   pass

class CustomHttpProxyNonTransparent(HttpProxyNonTransparent):
    def config(self):
        HttpProxyNonTransparent.config(self)
        self.connect_proxy = PlugProxy
        self.error_silent = TRUE

from passlib.apache import HtpasswdFile
class HtpasswdAuthenticationBackend(AbstractAuthenticationBackend):
    def __init__(self, htpasswd_file):
        self.htpasswd_file = htpasswd_file
        self.htpasswd_backend = HtpasswdFile(path=self.htpasswd_file)
        self.sessions = {}

    def startSession(self, session_id, session):
        pass

    def stopSession(self, session_id):
        del self.sessions[session_id]

    def getMethods(self, session_id, entity):
        user = None
        for (headername, value) in entity:
            if headername == "User":
                user = value
        if not user:
            log(session_id, CORE_AUTH, 1, "Could not parse user, rejecting;")
            return Z_AUTH_REJECT
        else:
            self.sessions[session_id] = user
        return (2, [('Method', 'PASSWD.NONE:0:0:Password Authentication/htpass')])

    def setMethod(self, session_id, method):
        return (4, [])

    def converse(self, session_id, credentials):
        passwd = None
        for (method, cred) in credentials:
            if method == "Password":
                passwd = cred
        if not passwd:
            log(session_id, CORE_AUTH, 1, "Could not parse password, rejecting;")
            return (Z_AUTH_REJECT, None)
        else:
            user = self.sessions[session_id]
            result = self.htpasswd_backend.check_password(user, passwd)
            if result == None:
                log(session_id, CORE_AUTH, 3, "Authentication failure, user account does not exist; username='%s'",
                    (user,)
                    )
                return (Z_AUTH_REJECT, None)
            elif result == True:
                groups = ["user",]
                log(session_id, CORE_AUTH, 4, "Authentication success; username='%s', groups='%s'",
                    (user, groups)
                    )
                return (Z_AUTH_ACCEPT, groups)
            log(session_id, CORE_AUTH, 3, "Authentication failure; username='%s'",
                (user,)
                )
            return (Z_AUTH_REJECT, None)

class BasicAuthHttpProxy(CustomHttpProxyNonTransparent):
    def config(self):
        super(BasicAuthHttpProxy, self).config()
        self.request["GET"] = (HTTP_REQ_POLICY, self.reqRedirect)
        self.request["POST"] = (HTTP_REQ_POLICY, self.reqRedirect)
        self.request["PUT"] = (HTTP_REQ_POLICY, self.reqRedirect)
        self.request["CONNECT"] = (HTTP_REQ_POLICY, self.reqRedirect)
        self.response["*", "*"] = (HTTP_RSP_POLICY, self.respRedirect)
        self.response_header["Authorization"] = (HTTP_HDR_DROP,)
        self.response_header["Proxy-Authorization"] = (HTTP_HDR_DROP,)
        self.authbackend = HtpasswdAuthenticationBackend('/etc/zorp/htpasswd')

    def __post_config__(self):
        super(BasicAuthHttpProxy, self).__post_config__()

    def authenticateUserPass(self, username, password):
        if self.authbackend.getMethods(self.session.session_id, [("User", username)]) != Z_AUTH_REJECT:
            self.authbackend.setMethod(self.session.session_id, "PASSWD.NONE:0:0:Password Authentication/inband")
            verdict = self.authbackend.converse(self.session.session_id, [("Password", password)])
            return verdict
        else:
            return Z_AUTH_REJECT

    def userAuthenticated(self, entity, groups=None, auth_info=''):
        proxyLog(self, CORE_AUTH, 3, "User authentication successful; entity='%s', auth_info='%s'", (entity, auth_info))
        self.session.auth_user = entity
        self.session.auth_groups = groups
        self.session.getMasterSession().auth_user = entity
        self.session.getMasterSession().auth_groups = groups
        self.session.auth_info = 'inband'
        return HTTP_REQ_ACCEPT

    def handleBasicAuth(self, authorization_header):
        if not authorization_header.startswith("Basic "):
            proxyLog(self, HTTP_POLICY, 1, "Unsupported authorization method; method='%s'", (authorization_header.strip().split(" ")[0], ))
            return HTTP_REQ_REJECT
        else:
            from base64 import b64decode
            try:
                userpasspart = authorization_header.strip().split(" ")[1]
                base64str = b64decode(userpasspart)
                username, password = base64str.split(":", 1)
            except Exception, e:
                raise AAException, "Unable to parse basic auth credentials: %s" % e
            verdict = self.authenticateUserPass(username, password)
            if verdict[0] == Z_AUTH_ACCEPT:
                self.userAuthenticated(username, verdict[1], "inband")
                return HTTP_REQ_ACCEPT
            raise AAException, "Authentication failed"

    def reqRedirect(self, method, url, version):
        authorization_header = self.getRequestHeader("Authorization")
        if not authorization_header:
            authorization_header = self.getRequestHeader("Proxy-Authorization")
        #check basic auth first
        if authorization_header:
            proxyLog(self, HTTP_POLICY, 6, "Authorization header found, proceeding with basic authentication")
            return self.handleBasicAuth(authorization_header)
        #force auth header
        else:
            self.error_status = 401
            self.error_msg = "Login required"
            self.error_info = "Login required"
            self.error_headers = "WWW-Authenticate: Basic realm=proxy\r\n"
        return HTTP_REQ_REJECT

    def respRedirect(self, method, url, version, response):
        if (self.session.auth_user or self.getRequestHeader("Authorization") or self.getRequestHeader("Proxy-Authorization")):
            return HTTP_RSP_ACCEPT
        raise AAException, "Unathenticated request"

def default():
  Service(name="service_http_nontransparent_inband", proxy_class=BasicAuthHttpProxy, router=InbandRouter(forge_port=TRUE, forge_addr=FALSE))
  Dispatcher(transparent=FALSE, bindto=DBIface(protocol=ZD_PROTO_TCP, port=3128, iface="eth0", family=2), rule_port="3128", service="service_http_nontransparent_inband")
  Dispatcher(transparent=FALSE, bindto=DBIface(protocol=ZD_PROTO_TCP, port=3128, iface="tap0", family=2), rule_port="3128", service="service_http_nontransparent_inband")
