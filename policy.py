from  Zorp.Core import  *
from  Zorp.Proxy import  *
from  Zorp.Http import  *
from  Zorp.Plug import  *
from  Zorp.Encryption import *

Zorp.firewall_name = 'zorp@docker'
config.options.kzorp_enabled = FALSE

class ConnnectHttpsProxy(HttpProxy):
   pass

class CustomHttpProxyNonTransparent(HttpProxyNonTransparent):
    def config(self):
        HttpProxyNonTransparent.config(self)
        self.connect_proxy = PlugProxy

def default():
  Service(name="service_http_nontransparent_inband", proxy_class=HttpProxyNonTransparent, router=InbandRouter(forge_port=TRUE, forge_addr=FALSE))
  Dispatcher(transparent=FALSE, bindto=DBIface(protocol=ZD_PROTO_TCP, port=3128, iface="eth0", family=2), rule_port="3128", service="service_http_nontransparent_inband")
  Dispatcher(transparent=FALSE, bindto=DBIface(protocol=ZD_PROTO_TCP, port=3128, iface="tap0", family=2), rule_port="3128", service="service_http_nontransparent_inband")
