# -*- coding: utf-8 -*-

import logging, logging.config, os
import requests


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


def hit_shib_url():
    URL = os.environ['ILL_SHB__EASYA_TEST_URL']
    r = requests.get( URL )
    log.debug( r.content )
    return r.content


def run_tunneler():
    st = ShibTunneler()
    st.access_vars_page()
    # st.post_auth_info()
    # st.parse_auth_info_response()
    # assert type(st.auth_info_response_params_dict) == dict, Exception( 'st.auth_info_response_params_dict not dict; validation failed' )
    # st.post_final()  # now st.json_vars has all apache headers, including shib headers
    return 'foo'


class ShibTunneler(object):
    '''
    - Purpose: to return apache shib header info to calling application.
    - Assumes SHIB_VARS_URL is a shib-protected page which, after successful authentication,
    returns json with keys of apache/shib header variables.
    - Note: capturing username/passwords, even briefly to pass on, is _not_ recommended;
    use only where:
    a) shib implementation does not offer forced reauthentication
    b) forced reauthentication is required
    - Usage:
    settings_dict = {
        'SHIB_VARS_URL': the-value,  # destination json apache/django/shib vars page
        'SHIB_POST_URL_A': the-value,  # shib auth form
        'SHIB_POST_URL_B': the-value,  # non-javascript confirmation form
        'USERNAME': the-value,
        'PASSWORD': the-value }
    st = ShibTunneler( settings=settings_dict )
    st.access_vars_page()
    assert type(st.auth_info_response_params_dict) == dict, Exception( 'st.auth_info_response_params_dict not dict; validation failed' )
    '''

    def __init__(self, settings=None ):
        if isinstance( settings, dict) :
            s = imp.new_module( 'settings' )
            for k, v in settings.items():
                setattr( s, k, v )
            settings = s
        self.SHIB_VARS_URL = os.environ['ILL_SHB__EASYA_TEST_URL']  # destination json apache/django/shib vars page
        self.SHIB_POST_URL_A = os.environ['ILL_SHB__SSO_AUTHN_URL']  # shib auth form
        self.SHIB_POST_URL_B = os.environ['ILL_SHB__IDP_POST_URL']  # non-javascript confirmation form
        self.USERNAME = os.environ['ILL_SHB__LOGIN_USERNAME']
        self.PASSWORD = os.environ['ILL_SHB__LOGIN_PASSWORD']
        self.cookies_a = None
        self.cookies_b = None
        self.auth_info_response_html = None
        self.auth_info_response_params_dict = None
        self.json_vars = None
        log.debug( 'tunneler instantiated' )

    def access_vars_page( self ):
        with requests.Session() as sess:
            requests.packages.urllib3.disable_warnings()
            r = sess.get( self.SHIB_VARS_URL, verify=False )
            self.cookies_a = r.cookies
            log.debug( 'vars-page initial html, ```{}```'.format( r.content.decode('utf-8', 'replace') ) )
            log.debug( '---' )
            log.debug( 'cookies_a, ```{}```'.format( self.cookies_a ) )
            log.debug( 'accessed vars-page' )
            sess = self.post_auth_info( sess )
            self.parse_auth_info_response()
            self.post_final( sess )
        return

    def post_auth_info( self, sess ):
        payload = {
            'j_password': self.PASSWORD, 'j_username': self.USERNAME }
        r2 = sess.post( self.SHIB_POST_URL_A, data=payload, verify=False )
        self.auth_info_response_html = r2.content.decode( 'utf-8', 'replace' )
        self.cookies_b = r2.cookies
        # log.debug( 'auth_info_response_html, ```{}```'.format( self.auth_info_response_html ) )
        log.debug( 'cookies_b, ```{}```'.format( self.cookies_b ) )
        log.debug( 'auth-info posted' )
        return sess

    def parse_auth_info_response( self ):
        from xml.dom import minidom
        try:
            xmldoc = minidom.parseString( self.auth_info_response_html )
        except Exception as e:
            log.error( 'error parsing auth_info_response_html, ```{err_a}```, ```{err_b}```'.format( err_a=e, err_b=repr(e) ) )
            return
        ## getting here means shib-auth was successful
        input_nodes = xmldoc.getElementsByTagName( 'input' )  # picks up the three input nodes (the two hidden_value ones and the submit one)
        values_dict = {}
        for input_node in input_nodes:
            if input_node.getAttributeNode( 'name' ) == None:  # ignore the 'submit' one
                pass
            elif input_node.getAttributeNode( 'name' ).nodeValue == 'RelayState':
                values_dict['RelayState'] = input_node.getAttributeNode( 'value' ).nodeValue
            elif input_node.getAttributeNode( 'name' ).nodeValue == 'SAMLResponse':
                values_dict['SAMLResponse'] = input_node.getAttributeNode( 'value' ).nodeValue
        assert sorted( values_dict.keys() ) == ['RelayState', 'SAMLResponse'], sorted( values_dict.keys() )
        self.auth_info_response_params_dict = values_dict
        log.debug( 'auth_info_response_params_dict, ```{}```'.format( self.auth_info_response_params_dict ) )
        log.debug( 'auth-info response parsed' )
        return

    def post_final( self, sess ):
        assert type(self.auth_info_response_params_dict) == dict
        payload = {
            'RelayState': self.auth_info_response_params_dict['RelayState'],
            'SAMLResponse': self.auth_info_response_params_dict['SAMLResponse'] }
        requests.packages.urllib3.disable_warnings()
        r3 = sess.post( self.SHIB_POST_URL_B, data=payload, verify=False )
        self.json_vars = r3.content.decode( 'utf-8', 'replace' )
        log.debug( 'json response, ```{}```'.format(self.json_vars) )
        log.debug( 'final post complete' )
        return

  # end class ShibTunneler()



if __name__ == '__main__':
    # hit_shib_url()
    run_tunneler()
