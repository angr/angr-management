//== Translate Substitute Module =============================================//

/**
 * For those not using Angular-Translate (pascalprecht.translate), this will sub
 * in for it so we don't have to include Angular-Translate if we don't want to.
 */

var translateSubMod = angular.module('translate.sub',[]);

	/**
	 * $translate Service
	 * Sets up a $translateProvider service to use in your module's config
	 * function.  $translate.Provider syntax is the same as Angular-Translate,
	 * use $translate.Provider.translations(lang,obj) to change the defaults
	 * for modal button, header and message text.
	 */
	translateSubMod.provider('$translate',[function(){
		var _translations = []; // object of key/value translation pairs
		var _current = 'en-US'; // default language

		/**
		 * Translations
		 * Set the internal object of translation key/value pairs.
		 */
		this.translations = function(lang,obj){
			if(angular.isDefined(lang) && angular.isDefined(obj)){
				_translations[lang] = angular.copy(obj);
				_current = lang;
			}
		}; // end translations

		this.$get = [function(){
			return {
				/**
				 * Instant
				 * Retrieve the translation for the given key, if key not found
				 * return an empty string.
				 * Example: $translate.instant('DIALOGS_OK');
				 */
				instant : function(what){
					if(angular.isDefined(what) && angular.isDefined(_translations[_current][what]))
						return _translations[_current][what];
					else
						return '';
				} // end instant
			}; // end return 
		}]; // end $get

	}]); // end $translate

	/**
	 * Translate Filter
	 * For use in an Angular template.  
	 * Example: {{"DIALOGS_CLOSE" | translate}}
	 */
	translateSubMod.filter('translate',['$translate',function($translate){
		return function(what){
			return $translate.instant(what);
		};
	}]); // end translate / translate.sub