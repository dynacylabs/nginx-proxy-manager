const Mn        = require('backbone.marionette');
const LoginView = require('./ui/login');
const Api       = require('../app/api');
const Tokens    = require('../app/tokens');

const App = Mn.Application.extend({
    region: '#login',
    UI:     null,

    onStart: function (/*app, options*/) {
        // Check if this is an OIDC callback
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        
        if (code && state) {
            this.handleOidcCallback(code, state);
        } else {
            this.getRegion().show(new LoginView());
        }
    },
    
    handleOidcCallback: function(code, state) {
        // Show loading
        const $loader = $('.loader');
        $loader.show();
        
        // Get stored OIDC session data
        const storedState = sessionStorage.getItem('oidc_state');
        const nonce = sessionStorage.getItem('oidc_nonce');
        const codeVerifier = sessionStorage.getItem('oidc_code_verifier');
        
        // Verify state matches
        if (state !== storedState) {
            console.error('OIDC state mismatch');
            sessionStorage.removeItem('oidc_state');
            sessionStorage.removeItem('oidc_nonce');
            sessionStorage.removeItem('oidc_code_verifier');
            this.getRegion().show(new LoginView());
            $loader.hide();
            return;
        }
        
        // Exchange code for token
        const redirectUri = window.location.origin + window.location.pathname;
        
        Api.OIDC.callback({
            code: code,
            state: state,
            nonce: nonce,
            code_verifier: codeVerifier,
            redirect_uri: redirectUri
        })
        .then(response => {
            // Clear session storage
            sessionStorage.removeItem('oidc_state');
            sessionStorage.removeItem('oidc_nonce');
            sessionStorage.removeItem('oidc_code_verifier');
            
            if (response.token) {
                Tokens.clearTokens();
                Tokens.addToken(response.token);
                
                // Redirect to main app
                window.location = '/';
            } else {
                throw new Error('No token returned from OIDC callback');
            }
        })
        .catch(err => {
            console.error('OIDC callback error:', err);
            sessionStorage.removeItem('oidc_state');
            sessionStorage.removeItem('oidc_nonce');
            sessionStorage.removeItem('oidc_code_verifier');
            
            // Show login page with error
            const loginView = new LoginView();
            this.getRegion().show(loginView);
            $loader.hide();
            
            // Show error message
            setTimeout(() => {
                $('.secret-error').text('OIDC authentication failed: ' + err.message).show();
            }, 100);
        });
    }
});

const app      = new App();
module.exports = app;
