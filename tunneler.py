# -*- coding: utf-8 -*-

import logging, logging.config, os
import requests
from xml.dom import minidom


log = logging.getLogger( 'illiad_shib_logger' )
logging_dct = {
    'disable_existing_loggers': True,
    'formatters': {'standard': {'datefmt': '%d/%b/%Y %H:%M:%S',
        'format': '[%(asctime)s] %(levelname)s [%(module)s-%(funcName)s()::%(lineno)d] %(message)s'} },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
            'level': 'DEBUG'} },
    "loggers": {
      "illiad_shib_logger": {
        "handlers": [
          "console"
        ],
        "level": "DEBUG"
      }
    },
    'version': 1
    }
logging.config.dictConfig( logging_dct )
log.debug( '\n---\nSTART\n---' )



def run_tunneler():
    st = ShibTunneler()
    json_data = st.access_vars_page()
    return json_data


class ShibTunneler(object):
    """
    Tunnels through shib with non-two-factor credentials.
    Usage:
        st = ShibTunneler()
        json_data = st.access_vars_page()
    """

    def __init__( self  ):
        self.SHIB_VARS_URL = os.environ['ILL_SHB__EASYA_TEST_URL']  # target json shib-vars page
        self.SHIB_POST_URL_A = os.environ['ILL_SHB__SSO_AUTHN_URL']  # IDP `Authn` url; for browser, would auto-redirect to initial target url
        self.SHIB_POST_URL_B = os.environ['ILL_SHB__IDP_POST_URL']  # IDP `SAML/POST` url; redirects on success to initial target url
        self.USERNAME = os.environ['ILL_SHB__LOGIN_USERNAME']
        self.PASSWORD = os.environ['ILL_SHB__LOGIN_PASSWORD']
        log.debug( 'tunneler instantiated' )

    def access_vars_page( self ):
        """ Tries desired url; is redirected to display of shib login page. """
        with requests.Session() as sess:
            requests.packages.urllib3.disable_warnings()
            r = sess.get( self.SHIB_VARS_URL, verify=False )
            log.debug( 'vars-page initial html, ```{}```\n---'.format( r.content.decode('utf-8', 'replace') ) )
            log.debug( 'accessed vars-page' )
            ( sess, auth_info_response_html ) = self.post_auth_info( sess )
            ( relay_state, saml_response ) = self.parse_auth_info_response( auth_info_response_html )
            jsn = self.post_final( sess, relay_state, saml_response )
        return jsn

    def post_auth_info( self, sess ):
        """ Posts username and password to IDP authentication url.
            Called by access_vars_page(). """
        payload = {
            'j_password': self.PASSWORD, 'j_username': self.USERNAME }
        r = sess.post( self.SHIB_POST_URL_A, data=payload, verify=False )
        auth_info_response_html = r.content.decode( 'utf-8', 'replace' )
        log.debug( 'auth_info_response_html, ```{}```'.format( auth_info_response_html ) )
        log.debug( 'auth-info posted' )
        return ( sess, auth_info_response_html )

    def parse_auth_info_response( self, auth_info_response_html ):
        """ Parses out `RelayState` and `SAMLResponse` response data.
            Called by access_vars_page() """
        xml_doc = self.docify_response( auth_info_response_html )  # getting here means shib-auth was successful
        input_nodes = xml_doc.getElementsByTagName( 'input' )  # picks up the three input nodes (the two hidden_value ones and the submit one)
        ( relay_state, saml_response ) = self.parse_input_nodes(  input_nodes )
        log.debug( 'auth-info response parsed' )
        return ( relay_state, saml_response )

    def docify_response( self, auth_info_response_html ):
        """ Converts html response into an xml-doc.
            Called by parse_auth_info_response() """
        try:
            xml_doc = minidom.parseString( auth_info_response_html )
            log.debug( 'html doc-ified' )
            return xml_doc
        except Exception as e:
            message = 'error parsing auth_info_response_html, ```{err_a}```, ```{err_b}```'.format( err_a=e, err_b=repr(e) )
            log.error( message )
            sys.exit( message )

    def parse_input_nodes( self, input_nodes ):
        """ Parses the three input nodes to grab `RelayState` and `SAMLResponse` data.
            Called by parse_auth_info_response() """
        ( relay_state, saml_response ) = ( None, None )
        for input_node in input_nodes:
            if input_node.getAttributeNode( 'name' ):  # ignore the 'submit' one
                if input_node.getAttributeNode( 'name' ).nodeValue == 'RelayState':
                    relay_state = input_node.getAttributeNode( 'value' ).nodeValue
                elif input_node.getAttributeNode( 'name' ).nodeValue == 'SAMLResponse':
                    saml_response = input_node.getAttributeNode( 'value' ).nodeValue
        # log.debug( 'relay_state, ```{rly}``` --||-- saml_response, ```{sml}```'.format( rly=relay_state, sml=saml_response ) )
        log.debug( 'input nodes parsed' )
        return ( relay_state, saml_response )

    def post_final( self, sess, relay_state, saml_response ):
        """ Posts `RelayState` and `SAMLResponse` data to the IDP `SAML/POST` url.
            Auto-performed in user-browser by javascript; must be explicitly called otherwise.
            Called by access_vars_page() """
        payload = {
            'RelayState': relay_state, 'SAMLResponse': saml_response }
        requests.packages.urllib3.disable_warnings()
        r = sess.post( self.SHIB_POST_URL_B, data=payload, verify=False )
        jsn = r.content.decode( 'utf-8', 'replace' )
        log.debug( 'json-data, ```{}```'.format(jsn) )
        log.debug( 'final post complete' )
        return jsn

  # end class ShibTunneler()



if __name__ == '__main__':
    run_tunneler()
