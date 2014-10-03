//== Services ================================================================//

angular.module('dialogs.services',['ui.bootstrap.modal','dialogs.controllers'])

	.provider('dialogs',[function(){
		var _b = true; // backdrop
		var _k = true; // keyboard
		var _w = 'dialogs-default'; // windowClass
		var _copy = true; // controls use of angular.copy
		var _wTmpl = null; // window template
		var _wSize = 'lg'; // large modal window default

		var _fa = false; // fontawesome flag

		var _setOpts = function(opts){
			var _opts = {};
			opts = opts || {};
			_opts.kb = (angular.isDefined(opts.keyboard)) ? opts.keyboard : _k; // values: true,false
			_opts.bd = (angular.isDefined(opts.backdrop)) ? opts.backdrop : _b; // values: 'static',true,false
			_opts.ws = (angular.isDefined(opts.size) && (angular.equals(opts.size,'sm') || angular.equals(opts.size,'lg') || angular.equals(opts.size,'md'))) ? opts.size : _wSize; // values: 'sm', 'lg', 'md'
			_opts.wc = (angular.isDefined(opts.windowClass)) ? opts.windowClass : _w; // additional CSS class(es) to be added to a modal window

			return _opts;
		}; // end _setOpts

		/**
		 * Use Backdrop
		 * 
		 * Sets the use of the modal backdrop.  Either to have one or not and
		 * whether or not it responds to mouse clicks ('static' sets the 
		 * backdrop to true and does not respond to mouse clicks).
		 *
		 * @param	val 	mixed	(true, false, 'static')
		 */
		this.useBackdrop = function(val){ // possible values : true, false, 'static'
			if(angular.isDefined(val))
				_b = val;
		}; // end useStaticBackdrop

		/**
		 * Use ESC Close
		 * 
		 * Sets the use of the ESC (escape) key to close modal windows.
		 *
		 * @param	val 	boolean
		 */
		this.useEscClose = function(val){ // possible values : true, false
			if(angular.isDefined(val))
				_k = (!angular.equals(val,0) && !angular.equals(val,'false') && !angular.equals(val,'no') && !angular.equals(val,null) && !angular.equals(val,false)) ? true : false;
		}; // end useESCClose

		/**
		 * Use Class
		 *
		 * Sets the additional CSS window class of the modal window template.
		 *
		 * @param	val 	string
		 */
		this.useClass = function(val){
			if(angular.isDefined(val))
				_w = val;
		}; // end useClass

		/**
		 * Use Copy
		 * 
		 * Determines the use of angular.copy when sending data to the modal controller.
		 *
		 * @param	val 	boolean
		 */
		this.useCopy = function(val){
			if(angular.isDefined(val))
				_copy = (!angular.equals(val,0) && !angular.equals(val,'false') && !angular.equals(val,'no') && !angular.equals(val,null) && !angular.equals(val,false)) ? true : false;
		}; // end useCopy

		/**
		 * Set Window Template
		 *
		 * Sets a path to a template to use overriding modal's window template.
		 *
		 * @param	val 	string
		 */
		this.setWindowTmpl = function(val){
			if(angular.isDefined(val))
				_wTmpl = val;
		}; // end setWindowTmpl

		/**
		 * Set Size
		 *
		 * Sets the modal size to use (sm,lg,md), requires Angular-ui-Bootstrap 0.11.0 and Bootstrap 3.1.0 + 
		 *
		 * @param	val 	string (sm,lg,md)
		 */
		this.setSize = function(val){
			if(angular.isDefined(val))
				_wSize = (angular.equals(val,'sm') || angular.equals(val,'lg') || angular.equals(val,'md')) ? val : _wSize;
		}; // end setSize

		/**
		 * Use Font-Awesome.
		 *
		 * Sets Font-Awesome flag to true and substitutes font-awesome icons for
		 * Bootstrap's glyphicons.
		 */
		this.useFontAwesome = function(){
			_fa = true;
		}; // end useFontAwesome


		this.$get = ['$modal',function ($modal){
			
			return {
				/**
				 * Error Dialog
				 *
				 * @param	header 	string
				 * @param	msg 	string
				 * @param	opts	object
				 */
				error : function(header,msg,opts){
					opts = _setOpts(opts);

					return $modal.open({
						templateUrl : '/dialogs/error.html',
						controller : 'errorDialogCtrl',
						backdrop: opts.bd,
						keyboard: opts.kb,
						windowClass: opts.wc,
						size: opts.ws,
						resolve : {
							data : function(){
								return {
									header : angular.copy(header),
									msg : angular.copy(msg),
									fa : _fa
								};
							}
						}
					}); // end modal.open
				}, // end error
				
				/**
				 * Wait Dialog
				 *
				 * @param	header 		string
				 * @param	msg 		string
				 * @param	progress 	int
				 * @param	opts	object
				 */
				wait : function(header,msg,progress,opts){
					opts = _setOpts(opts);

					return $modal.open({
						templateUrl : '/dialogs/wait.html',
						controller : 'waitDialogCtrl',
						backdrop: opts.bd,
						keyboard: opts.kb,
						windowClass: opts.wc,
						size: opts.ws,
						resolve : {
							data : function(){
								return {
									header : angular.copy(header),
									msg : angular.copy(msg),
									progress : angular.copy(progress),
									fa : _fa
								};
							}
						}
					}); // end modal.open
				}, // end wait
				
				/**
				 * Notify Dialog
				 *
				 * @param	header 		string
				 * @param	msg 		string
				 * @param	opts	object
				 */
				notify : function(header,msg,opts){
					opts = _setOpts(opts);

					return $modal.open({
						templateUrl : '/dialogs/notify.html',
						controller : 'notifyDialogCtrl',
						backdrop: opts.bd,
						keyboard: opts.kb,
						windowClass: opts.wc,
						size: opts.ws,
						resolve : {
							data : function(){
								return {
									header : angular.copy(header),
									msg : angular.copy(msg),
									fa : _fa
								};
							}
						}
					}); // end modal.open
				}, // end notify
				
				/**
				 * Confirm Dialog
				 *
				 * @param	header 	string
				 * @param	msg 	string
				 * @param	opts	object
				 */
				confirm : function(header,msg,opts){
					opts = _setOpts(opts);

					return $modal.open({
						templateUrl : '/dialogs/confirm.html',
						controller : 'confirmDialogCtrl',
						backdrop: opts.bd,
						keyboard: opts.kb,
						windowClass: opts.wc,
						size: opts.ws,
						resolve : {
							data : function(){
								return {
									header : angular.copy(header),
									msg : angular.copy(msg),
									fa : _fa
								};
							}
						}
					}); // end modal.open
				}, // end confirm
				
				/**
				 * Create Custom Dialog
				 *
				 * @param	url 	string
				 * @param	ctrlr 	string
				 * @param	data 	object
				 * @param	opts	object
				 */
				create : function(url,ctrlr,data,opts){
					var copy = (opts && angular.isDefined(opts.copy)) ? opts.copy : _copy;
					opts = _setOpts(opts);

					return $modal.open({
						templateUrl : url,
						controller : ctrlr,
						keyboard : opts.kb,
						backdrop : opts.bd,
						windowClass: opts.wc,
						size: opts.ws,
						resolve : {
							data : function() { 
								if(copy)
									return angular.copy(data);
								else
									return data;
							}
						}
					}); // end modal.open
				} // end create

			}; // end return

		}]; // end $get
	}]); // end provider dialogs