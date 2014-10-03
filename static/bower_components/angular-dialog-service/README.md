Angular Dialog Service
======================

>**Please use one of the release versions rather than the Master Branch**.  The Master Branch has untested merges and changes and is a work in progress.  I urge you to always use a release version rather than linking directly to the Master Branch, as the Master Branch may change and may not always be backward compatible.

**v4.x.x + is not backward compatible with versions 1,2,3,3.1  Please refer to the changes section to view what is different in v4.0**

A complete AngularJS service with controllers and templates for generating application modals and dialogs for use with Angular-UI-Bootstrap and Twitter Bootstrap.  Supports, i18n, language translations for dialog headers, messages and buttons via angular-translate.

Demos
-----
 - v1.0 : [Codepen: http://codepen.io/m-e-conroy/pen/ALsdF](http://codepen.io/m-e-conroy/pen/ALsdF)
 - v2.0 : [Codepen: http://codepen.io/m-e-conroy/pen/AmBpL](http://codepen.io/m-e-conroy/pen/AmBpL)
 - v4.2 : [Codepen: http://codepen.io/m-e-conroy/pen/rkIqv](http://codepen.io/m-e-conroy/pen/rkIqv)
 - v4.2 : [Codepen: with UI-Bootstrap Date Picker directive](http://codepen.io/m-e-conroy/pen/DAxzs) 

Release Versions
----------------
- v1.0 : supports AngularJS 1.1.5 and below.
- v2.0 : supports AngularJS 1.2 +
- v3.0 : supports AngularJS 1.2 +, Angular UI Bootstrap 0.10.0
- v4.0.0 - v4.1.0 : supports AngularJS 1.2 +, Angular UI Bootstrap 0.10.0, Bootstrap 3 +
- v4.2.0 - v5.x.x+ : supports AngularJS 1.2 +, Angular UI Bootstrap 0.11.0, Bootstrap 3.1 +
 
v5.1.3
------
1. Bug fixes with regards to v5.1.2 #2 (issue #64)

v5.1.2
------
1. Bug fix for _setOpts (issue #61).
2. Changed the way resolved *header* and *msg* data is passed to the controller, so it would be easier to **decorate** each service if one so desires (issue #60).

v5.1.0
------
1. Fixed Wait dialog template, header should now display a passed parameter header to the wait service.  Prior to this it would always display the default header whether or not a passed header parameter was used or not.
2. Default translations have been removed from the dialogs.main module to their own module, in order to support applications that were already using Angular-Translate and had already defined translation lists for 'en-US.'  Previously including dialogs.main would have overwritten those translation lists supplied elsewhere in an application.  To use the default translations:
	- Include the dialogs-default-translations.min.js file in your HTML file and add 'dialogs.default-translations' to your application's dependency list along with 'dialogs.main'
	- OR If you already had a translation list setup elsewhere in your application just copy the $translationProvider translation list in the dialogs-default-translations module to where-ever it is that you have your list configured

v5.0.0
------
Re-introduction of the [opts] parameter to dialogs methods.  I had many complaints about removing method level options in favor of wholly using the provider instead.

1. dialogs.error(header,msg[,opts])
2. dialogs.wait(header,msg,progress[,opts])
3. dialogs.notify(header,msg[,opts])
4. dialogs.confirm(header,msg[,opts])
5. dialogs.create(url,ctrlr,data[,opts])

v4.2.0
------
Bootstrap 3.1.1 / Angular UI Bootstrap 0.11.0 introduced a size property for dialogs.  This can be controlled via the provider or by the optional *sz* parameter to the dialog methods.

1. dialogs.error(header,msg[,sz])
2. dialogs.wait(header,msg,progress[,sz])
3. dialogs.notify(header,msg[,sz])
4. dialogs.confirm(header,msg[,sz])
5. dialogs.create(url,ctrlr,data[,sz])

v4.0.0 - 4.1.0
--------------
Removed *opts* and *static* parameters from dialog methods in favor of provider settings.  The dialogs service is now longer **$dialogs**, the *\$* has be removed as this is reserved for Angular core services.

1. dialogs.error(header,msg)
2. dialogs.wait(header,msg,progress)
3. dialogs.notify(header,msg)
4. dialogs.confirm(header,msg)
5. dialogs.create(url,ctrlr,data)

v1.0 - v3.1.0
-------------
Predefined dialogs/modals.

1. $dialogs.error(header,msg,[static])
2. $dialogs.wait(header,msg,progess,[static])
3. $dialogs.notify(header,msg,[static])
4. $dialogs.confirm(header,msg,[static])
5. $dialogs.create(url,ctrlr,data,opts)

Dependencies
------------

v1.0
----

1.  [Angular JS](http://www.angularjs.org) (version 1.1.5 and less) 
2.  [Angular UI Bootstrap](http://angular-ui.github.io/bootstrap/#/modal) (version <= 0.6.0, Non-Bootstrap 3 Branch) with embedded templates.
3.  [Twitter Bootstrap CSS](http://getbootstrap.com) (version 2)

v2.0 Additional Dependencies
----------------------------
1.  All version 1.0 dependencies.
2.  [Angular JS ngSanitize](http://code.angularjs.org/1.2.1/angular-sanitize.min.js)
	- [ngSanitize](http://docs.angularjs.org/api/ngSanitize) (needed for ng-bind-html)

v3.0
----

1.  AngularJS 1.2 +
2.  Angular UI Bootstrap 0.10.0
3.  Twitter Bootstrap CSS 3.0.3
4.  AngularJS ngSanitize

v4.0.0 - v4.1.0
---------------

1. AngularJS 1.2 +
2. [Angular UI Bootstrap Modal 0.10.0, with templates](http://angular-ui.github.io/bootstrap/#/modal)
3. Twitter Bootstrap CSS 3 + (includes 3.1.1)
4. Angular ngSanitize
5. [Angular Translate](https://github.com/angular-translate)

v4.2.0 & v5.x.x
---------------
Same as v4.0.0 with the exception of the following:

1. [Angular UI Bootstrap Modal 0.11.0, with templates](http://angular-ui.github.io/bootstrap/#/modal)
2. [Twitter Bootstrap CSS 3.1.x](http://getbootstrap.com)

CSS
---
Included a css file that has a .modal class fix for Bootstrap and also has some predefined styles for the various modals described in the service.

**v3.0 css file has the .modal class removed that had been a fix for a Bootstrap 3 display problem.  This has since been rectified by Angular UI and Bootstrap.**

Changes
-------

- v3.0

1.  Added support for Angular UI Bootstrap 0.10.0.
2.  Added the ability to customize the header on the error and wait dialogs.
3.  Added example files.

- v4.0.0 - v4.1.0

1.  Removed *\$* from the *\$dialogs* service as this is reserved for core AngularJS naming.  The service is now just *dialogs.*  Include **dialogs.main** in your application module in order to use the the *dialogs* service
2.  Changed *dialogs* service from factory to provider, you can now use **dialogsProvider** to set various options of the modals that were previously passed as parameters to the dialogs' service methods.
	- **dialogsProvider.useBackdrop([true,false,'static'])** - True or false to use a backdrop for the modal, 'static' to use a backdrop and disallow closing on mouse click of the backdrop.
	- **dialogsProvider.useEscClose([true,false])** - Whether or not to allow the use of the 'ESC' key to close the modal
	- **dialogsProvider.useClass([string])** - Sets an additional CSS class to the modal window
	- **dialogsProvider.useCopy([true,false])** - Determines whether to use angular.copy or not when passing a data object to the custom dialog service.  Setting this to false will allow the modal to retain the two-way binding with the calling controller - thus changing data in the modal will automatically change it in the calling controller's scope.  The default is setting is true, so if you want the two-way binding you need to set this to false. 
3.  Main module is no longer *dialogs* as this would conflict with the new naming of the service.  It is now *dialogs.main,* include that in your application's module definition to use the *dialogs* service.
4.  Added i18n support via [Angular-Translate](https://github.com/angular-translate), use the *$translateProvider* to set language specific defaults.  Default language is currently *en-US.*  An example is provided in the example folder that will show you how to change the defaults from English to Spanish.  Translations can be set on the following:
	- DIALOGS_ERROR (modal header)
	- DIALOGS_ERROR_MSG
	- DIALOGS_CLOSE (modal button)
	- DIALOGS_PLEASE_WAIT (modal header)
	- DIALOGS_PLEASE_WAIT_ELIPS (modal header)
	- DIALOGS_PLEASE_WAIT_MSG
	- DIALOGS_PERCENT_COMPLETE (modal message partial)
	- DIALOGS_NOTIFICATION (modal header)
	- DIALOGS_NOTIFICATION_MSG
	- DIALOGS_CONFIRMATION (modal header)
	- DIALOGS_CONFIRMATION_MSG
	- DIALOGS_OK (modal button)
	- DIALOGS_YES (modal button)
	- DIALOGS_NO (modal button)

- v4.2.0

1. Supports everything described above in v4.0.0 - v4.1.0 and added the following

2. dialogsProvider.setSize(['sm','lg']) - This will set modal size application wide, but can be overridden using the *sz* parameter added to each dialog method call.

- v5.0.0

1. Optionally pass in options object, possible overrides are as follows

   ```
   opts = {
        'keyboard': true or false
        'backdrop': 'static' or true or false
        'size': 'sm' or 'lg' //small or large modal size
        'windowClass': 'dialogs-default' // additional CSS class(es) to be added to a modal window
        'copy': true or false // used only with create custom dialog
    }
    ```

- v5.1.0

1. Separated out the default translations into their own module: **dialogs-default-translations.js**  Include this or the "min" version in your application if you are not already using $translationProvider elsewhere, otherwise just copy the translation list within the module to your translation list for 'en-US.'

Notes
-----

- Angular Translate: v4.0 requires [Angular-Translate](https://github.com/angular-translate) be included.
- Bootstrap 3: There's a problem with the actual modal being displayed even though it appears in the HTML code to be present.  I found that adding a "display: block" to Bootstrap 3's .modal class solved the problem. *(v3.0 of this service no longer requires this fix)*
- It should not rely on including the Bootstrap JS.
- For version 2.0 + of this service module do not forget to include the *ngSanitize* Angular module.


> Written with [StackEdit](https://stackedit.io/).
