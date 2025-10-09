const Mn       = require('backbone.marionette');
const App      = require('../../main');
const template = require('./form.ejs');

module.exports = Mn.View.extend({
    template: template,
    className: 'modal-dialog',

    ui: {
        form:            'form',
        buttons:         'form button',
        cancel:          'button.cancel',
        save:            'button.save',
        enabled:         'input[name="enabled"]',
        issuer_url:      'input[name="issuer_url"]',
        client_id:       'input[name="client_id"]',
        client_secret:   'input[name="client_secret"]',
        redirect_uri:    'input[name="redirect_uri"]',
        scope:           'input[name="scope"]',
        auto_provision:  'input[name="auto_provision"]',
        default_role:    'select[name="default_role"]',
        provider_name:   'input[name="provider_name"]',
        button_text:     'input[name="button_text"]',
        test:            'button.test'
    },

    events: {
        'click @ui.save': function (e) {
            e.preventDefault();
            
            if (!this.ui.form[0].checkValidity()) {
                $('<input type="submit">').hide().appendTo(this.ui.form).click().remove();
                return;
            }

            let view = this;
            let data = {
                enabled:        this.ui.enabled.prop('checked'),
                issuer_url:     this.ui.issuer_url.val(),
                client_id:      this.ui.client_id.val(),
                client_secret:  this.ui.client_secret.val(),
                redirect_uri:   this.ui.redirect_uri.val(),
                scope:          this.ui.scope.val() || 'openid email profile',
                auto_provision: this.ui.auto_provision.prop('checked'),
                default_role:   this.ui.default_role.val(),
                provider_name:  this.ui.provider_name.val() || 'OIDC',
                button_text:    this.ui.button_text.val() || 'Sign in with OIDC'
            };

            this.ui.buttons.prop('disabled', true).addClass('btn-disabled');

            App.Api.OIDC.updateConfig(data)
                .then(() => {
                    view.trigger('saved');
                    App.UI.closeModal();
                })
                .catch(err => {
                    alert(err.message);
                    view.ui.buttons.prop('disabled', false).removeClass('btn-disabled');
                });
        },
        
        'click @ui.test': function (e) {
            e.preventDefault();
            
            if (!this.ui.issuer_url.val()) {
                alert('Please enter an Issuer URL first');
                return;
            }
            
            if (!this.ui.client_id.val()) {
                alert('Please enter a Client ID first');
                return;
            }
            
            if (!this.ui.client_secret.val()) {
                alert('Please enter a Client Secret first');
                return;
            }
            
            this.ui.test.addClass('btn-loading').prop('disabled', true);
            
            // Gather current form data for testing
            const testData = {
                issuer_url: this.ui.issuer_url.val(),
                client_id: this.ui.client_id.val(),
                client_secret: this.ui.client_secret.val(),
                redirect_uri: this.ui.redirect_uri.val() || window.location.origin + '/login'
            };
            
            // Test OIDC configuration
            App.Api.OIDC.testConfig(testData)
                .then(result => {
                    alert('OIDC configuration test successful!\n\nIssuer: ' + result.issuer);
                })
                .catch(err => {
                    alert('OIDC configuration test failed: ' + err.message);
                })
                .finally(() => {
                    this.ui.test.removeClass('btn-loading').prop('disabled', false);
                });
        }
    },

    templateContext: function() {
        return {
            config: this.config || {}
        };
    },

    onRender: function () {
        // Load current config
        App.Api.OIDC.getConfig()
            .then(config => {
                if (config && config.enabled !== undefined) {
                    this.config = config;
                    
                    // Populate form
                    this.ui.enabled.prop('checked', config.enabled || false);
                    this.ui.issuer_url.val(config.issuer_url || '');
                    this.ui.client_id.val(config.client_id || '');
                    this.ui.client_secret.val(config.client_secret || '');
                    this.ui.redirect_uri.val(config.redirect_uri || window.location.origin + '/login');
                    this.ui.scope.val(config.scope || 'openid email profile');
                    this.ui.auto_provision.prop('checked', config.auto_provision !== false);
                    this.ui.default_role.val(config.default_role || 'user');
                    this.ui.provider_name.val(config.provider_name || 'OIDC');
                    this.ui.button_text.val(config.button_text || 'Sign in with OIDC');
                }
            })
            .catch(err => {
                console.error('Failed to load OIDC config:', err);
            });
    }
});
