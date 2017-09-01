<?php
namespace Drupal\auth0\Form;

/**
 * @file
 * Contains \Drupal\auth0\Form\BasicAdvancedForm.
 */

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * This forms handles the advanced module configurations.
 */
class BasicAdvancedForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'auth0_basic_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $form['auth0_form_title'] = array(
        '#type' => 'textfield',
        '#title' => t('Form title'),
        '#default_value' => $config->get('auth0_form_title', 'Sign In'),
        '#description' => t('This is the title for the login widget.')
    );

    $form['auth0_allow_signup'] = array(
        '#type' => 'checkbox',
        '#title' => t('Allow user signup'),
        '#default_value' => $config->get('auth0_allow_signup'),
        '#description' => t('If you have database connection you can allow users to signup in the widget.')
    );

    $form['auth0_widget_cdn'] = array(
        '#type' => 'textfield',
        '#title' => t('Widget CDN'),
        '#default_value' => $config->get('auth0_widget_cdn'),
        '#description' => t('Point this to the latest widget available in the CDN.')
    );

    $form['auth0_requires_verified_email'] = array(
        '#type' => 'checkbox',
        '#title' => t('Requires verified email'),
        '#default_value' => $config->get('auth0_requires_verified_email'),
        '#description' => t('Mark this if you require the user to have a verified email to login.')
    );

    $form['auth0_join_user_by_mail_enabled'] = array(
      '#type' => 'checkbox',
      '#title' => t('Link auth0 logins to drupal users by email address'),
      '#default_value' => $config->get('auth0_join_user_by_mail_enabled'),
      '#description' => t('If enabled, when a user logs into Drupal for the first time, the system will use the email 
address of the Auth0 user to search for a drupal user with the same email address and setup a link to that 
Drupal user account.
<br/>If not enabled, then a new Drupal user will be created even if a Drupal user with the same email address already exists.
')
    );

    $form['auth0_username_claim'] = array(
      '#type' => 'textfield',
      '#title' => t('Map Auth0 claim to Drupal user name.'),
      '#default_value' => $config->get('auth0_username_claim', 'nickname'),
      '#description' => t('Maps the given claim field as the Drupal user name field. The default is the nickname claim'),
    );
    
    $form['auth0_login_css'] = array(
        '#type' => 'textarea',
        '#title' => t('Login widget css'),
        '#default_value' => $config->get('auth0_login_css'),
        '#description' => t('This css controls how the widget look and feel.')
    );

    $form['auth0_lock_extra_settings'] = array(
        '#type' => 'textarea',
        '#title' => t('Lock extra settings'),
        '#default_value' => $config->get('auth0_lock_extra_settings'),
        '#description' => t('This should be a valid JSON file. This entire object will be passed to the lock options parameter.')
    );

    $form['auth0_auto_register'] = array(
      '#type' => 'checkbox',
      '#title' => t('Auto Register Auth0 users (ignore site registration settings)'),
      '#default_value' => $config->get('auth0_auto_register', FALSE),
      '#description' => t('Enable this option if you want new auth0 users to automatically be activated within Drupal regardless of the global site visitor registration settings (e.g. requiring admin approval).'),
    );

    // Enhancement to support mapping claims to user attributes and to roles
    $form['auth0_claim_mapping'] = array(
      '#type' => 'textarea',
      '#title' => t('Mapping of Claims to Profile Fields (one per line):'),
      '#cols' => 50,
      '#rows' => 5,
      '#default_value' => $config->get('auth0_claim_mapping'),
      '#description' => t('Enter claim mappings here in the format &lt;claim_name>|&lt;profile_field_name> (one per line), e.g:
<br/>given_name|field_first_name
<br/>family_name|field_last_name
<br/>
<br/>NOTE: the following Drupal fields are handled automatically and will be ignored if specified above:
<br/>    uid, name, mail, init, is_new, status, pass
<br/>&nbsp;
'),
    );

    $form['auth0_claim_to_use_for_role'] = array(
      '#type' => 'textfield',
      '#title' => t('Claim for Role Mapping:'),
      '#default_value' => $config->get('auth0_claim_to_use_for_role'),
      '#description' => t('Name of the claim to use to map to Drupal roles, e.g. roles.  If the claim contains a list of values, all values will be used in the mappings below.')
    );

    $form['auth0_role_mapping'] = array(
      '#type' => 'textarea',
      '#title' => t('Mapping of Claim Role Values to Drupal Roles (one per line)'),
      '#default_value' => $config->get('auth0_role_mapping'),
      '#description' => t('Enter role mappings here in the format &lt;auth0 claim value>|&lt;drupal role name> (one per line), e.g.:
<br/>admin|administrator
<br/>poweruser|power users
<br/>
<br/>NOTE: for any drupal role in the mapping, if a user is not mapped to the role, the role will be removed from their profile.
Drupal roles not listed above will not be changed by this module.
<br/>&nbsp;
')
    );


    $form['actions']['#type'] = 'actions';
    $form['actions']['submit'] = array(
      '#type' => 'submit',
      '#value' => $this->t('Save'),
      '#button_type' => 'primary',
    );
    return $form;

  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $config = \Drupal::service('config.factory')->getEditable('auth0.settings');
    $config->set('auth0_form_title', $form_state->getValue('auth0_form_title'))
            ->set('auth0_allow_signup', $form_state->getValue('auth0_allow_signup'))
            ->set('auth0_widget_cdn', $form_state->getValue('auth0_widget_cdn'))
            ->set('auth0_requires_verified_email', $form_state->getValue('auth0_requires_verified_email'))
            ->set('auth0_join_user_by_mail_enabled', $form_state->getValue('auth0_join_user_by_mail_enabled'))
            ->set('auth0_login_css', $form_state->getValue('auth0_login_css'))
            ->set('auth0_auto_register', $form_state->getValue('auth0_auto_register'))
            ->set('auth0_lock_extra_settings', $form_state->getValue('auth0_lock_extra_settings'))
            ->set('auth0_claim_mapping', $form_state->getValue('auth0_claim_mapping'))
            ->set('auth0_claim_to_use_for_role', $form_state->getValue('auth0_claim_to_use_for_role'))
            ->set('auth0_role_mapping', $form_state->getValue('auth0_role_mapping'))
            ->save();
  }

}