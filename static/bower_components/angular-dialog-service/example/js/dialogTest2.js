angular.module('modalTest',['ui.bootstrap','dialogs.main'])
	
	.controller('dialogServiceTest',function($scope,$rootScope,$timeout,dialogs){

		//-- Variables --//

		var _progress = 33;

		$scope.name = '';
		$scope.confirmed = 'No confirmation yet!';
		
		$scope.custom = {
			val: 'Initial Value'
		};

		//-- Methods --//

		$scope.launch = function(which){
			switch(which){
				case 'error':
					dialogs.error();
					break;
				case 'wait':
					var dlg = dialogs.wait(undefined,undefined,_progress);
					_fakeWaitProgress();
					break;
				case 'customwait':
					var dlg = dialogs.wait('Custom Wait Header','Custom Wait Message',_progress);
					_fakeWaitProgress();
					break;
				case 'notify':
					dialogs.notify();
					break;
				case 'confirm':
					var dlg = dialogs.confirm();
					dlg.result.then(function(btn){
						$scope.confirmed = 'You confirmed "Yes."';
					},function(btn){
						$scope.confirmed = 'You confirmed "No."';
					});
					break;
				case 'custom':
					var dlg = dialogs.create('/dialogs/custom.html','customDialogCtrl',{},{size:'lg',keyboard: true,backdrop: false,windowClass: 'my-class'});
					dlg.result.then(function(name){
						$scope.name = name;
					},function(){
						if(angular.equals($scope.name,''))
							$scope.name = 'You did not enter in your name!';
					});
					break;
				case 'custom2':
					var dlg = dialogs.create('/dialogs/custom2.html','customDialogCtrl2',$scope.custom,{size:'lg'});
					break;
			}
		}; // end launch

		var _fakeWaitProgress = function(){
			$timeout(function(){
				if(_progress < 100){
					_progress += 33;
					$rootScope.$broadcast('dialogs.wait.progress',{'progress' : _progress});
					_fakeWaitProgress();
				}else{
					$rootScope.$broadcast('dialogs.wait.complete');
					_progress = 33;
				}
			},1000);
		}; // end _fakeWaitProgress

	})

	.controller('customDialogCtrl',function($scope,$modalInstance,data){
		//-- Variables --//

		$scope.user = {name : ''};

		//-- Methods --//
		
		$scope.cancel = function(){
			$modalInstance.dismiss('Canceled');
		}; // end cancel
		
		$scope.save = function(){
			$modalInstance.close($scope.user.name);
		}; // end save
		
		$scope.hitEnter = function(evt){
			if(angular.equals(evt.keyCode,13) && !(angular.equals($scope.user.name,null) || angular.equals($scope.user.name,'')))
				$scope.save();
		};
	}) // end controller(customDialogCtrl)
	
	.controller('customDialogCtrl2',function($scope,$modalInstance,data){
		
		$scope.data = data;
		
		//-- Methods --//
		
		$scope.done = function(){
			$modalInstance.close($scope.data);
		}; // end done
		
		$scope.hitEnter = function(evt){
			if(angular.equals(evt.keyCode,13) && !(angular.equals($scope.user.name,null) || angular.equals($scope.user.name,'')))
				$scope.done();
		};
	})

	.config(function($translateProvider){
		/**
		 * These are the defaults set by the dialogs.main module when Angular-Translate
		 * is not loaded.  You can reset them in your module's configuration
		 * function by using $translateProvider.  If you want to use these when
		 * Angular-Translate is used and loaded, then you need to also load
		 * dialogs-default-translations.js or include them where you are setting
		 * translations in your module.  These were separated out when Angular-Translate
		 * is loaded so as not to clobber translation set elsewhere in one's 
		 * application.
		 
		$translateProvider.translations('en-US',{
	        DIALOGS_ERROR: "Error",
	        DIALOGS_ERROR_MSG: "An unknown error has occurred.",
	        DIALOGS_CLOSE: "Close",
	        DIALOGS_PLEASE_WAIT: "Please Wait",
	        DIALOGS_PLEASE_WAIT_ELIPS: "Please Wait...",
	        DIALOGS_PLEASE_WAIT_MSG: "Waiting on operation to complete.",
	        DIALOGS_PERCENT_COMPLETE: "% Complete",
	        DIALOGS_NOTIFICATION: "Notification",
	        DIALOGS_NOTIFICATION_MSG: "Unknown application notification.",
	        DIALOGS_CONFIRMATION: "Confirmation",
	        DIALOGS_CONFIRMATION_MSG: "Confirmation required.",
	        DIALOGS_OK: "OK",
	        DIALOGS_YES: "Yes",
	        DIALOGS_NO: "No"
        });
		*/
	})

	.run(function($templateCache){
		$templateCache.put('/dialogs/custom.html','<div class="modal-header"><h4 class="modal-title"><span class="glyphicon glyphicon-star"></span> User\'s Name</h4></div><div class="modal-body"><ng-form name="nameDialog" novalidate role="form"><div class="form-group input-group-lg" ng-class="{true: \'has-error\'}[nameDialog.username.$dirty && nameDialog.username.$invalid]"><label class="control-label" for="course">Name:</label><input type="text" class="form-control" name="username" id="username" ng-model="user.name" ng-keyup="hitEnter($event)" required><span class="help-block">Enter your full name, first &amp; last.</span></div></ng-form></div><div class="modal-footer"><button type="button" class="btn btn-default" ng-click="cancel()">Cancel</button><button type="button" class="btn btn-primary" ng-click="save()" ng-disabled="(nameDialog.$dirty && nameDialog.$invalid) || nameDialog.$pristine">Save</button></div>');
  		$templateCache.put('/dialogs/custom2.html','<div class="modal-header"><h4 class="modal-title"><span class="glyphicon glyphicon-star"></span> Custom Dialog 2</h4></div><div class="modal-body"><label class="control-label" for="customValue">Custom Value:</label><input type="text" class="form-control" id="customValue" ng-model="data.val" ng-keyup="hitEnter($event)"><span class="help-block">Using "dialogsProvider.useCopy(false)" in your applications config function will allow data passed to a custom dialog to retain its two-way binding with the scope of the calling controller.</span></div><div class="modal-footer"><button type="button" class="btn btn-default" ng-click="done()">Done</button></div>');
	});
	