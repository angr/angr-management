//== Controllers =============================================================//

var ctrlrs; // will be dialogs.controllers module

// determine if Angular-Translate is available, if not use the substitute
try{
	angular.module('pascalprecht.translate'); // throws error if module not loaded
	console.log('Dialogs (Angular-Translate): OK');
	
	// dialogs.controllers: module declaration
	ctrlrs = angular.module('dialogs.controllers',['ui.bootstrap.modal','pascalprecht.translate']);
}catch(err){
	console.log('Dialogs: (Angular-Translate): ' + err.message);
	console.log('Dialogs: Attempting to use translate.sub module.');

	// dialogs.controllers: module declaration
	ctrlrs = angular.module('dialogs.controllers',['ui.bootstrap.modal','translate.sub']);
} // end try/catch

// angular.module('dialogs.controllers',['ui.bootstrap.modal','pascalprecht.translate'])

/**
 * Error Dialog Controller 
 */
ctrlrs.controller('errorDialogCtrl',['$scope','$modalInstance','$translate','data',function($scope,$modalInstance,$translate,data){
	//-- Variables -----//

	$scope.header = (angular.isDefined(data.header)) ? data.header : $translate.instant('DIALOGS_ERROR');
	$scope.msg = (angular.isDefined(data.msg)) ? data.msg : $translate.instant('DIALOGS_ERROR_MSG');
	$scope.icon = (angular.isDefined(data.fa) && angular.equals(data.fa,true)) ? 'fa fa-warning' : 'glyphicon glyphicon-warning-sign';

	//-- Methods -----//
	
	$scope.close = function(){
		$modalInstance.close();
		$scope.$destroy();
	}; // end close
}]); // end ErrorDialogCtrl
	
/**
 * Wait Dialog Controller 
 */
ctrlrs.controller('waitDialogCtrl',['$scope','$modalInstance','$translate','$timeout','data',function($scope,$modalInstance,$translate,$timeout,data){
	//-- Variables -----//

	$scope.header = (angular.isDefined(data.header)) ? data.header : $translate.instant('DIALOGS_PLEASE_WAIT_ELIPS');
	$scope.msg = (angular.isDefined(data.msg)) ? data.msg : $translate.instant('DIALOGS_PLEASE_WAIT_MSG');
	$scope.progress = (angular.isDefined(data.progress)) ? data.progress : 100;
	$scope.icon = (angular.isDefined(data.fa) && angular.equals(data.fa,true)) ? 'fa fa-clock-o' : 'glyphicon glyphicon-time';

	//-- Listeners -----//
	
	// Note: used $timeout instead of $scope.$apply() because I was getting a $$nextSibling error
	
	// close wait dialog
	$scope.$on('dialogs.wait.complete',function(){
		$timeout(function(){ $modalInstance.close(); $scope.$destroy(); });
	}); // end on(dialogs.wait.complete)
	
	// update the dialog's message
	$scope.$on('dialogs.wait.message',function(evt,args){
		$scope.msg = (angular.isDefined(args.msg)) ? args.msg : $scope.msg;
	}); // end on(dialogs.wait.message)
	
	// update the dialog's progress (bar) and/or message
	$scope.$on('dialogs.wait.progress',function(evt,args){
		$scope.msg = (angular.isDefined(args.msg)) ? args.msg : $scope.msg;
		$scope.progress = (angular.isDefined(args.progress)) ? args.progress : $scope.progress;
	}); // end on(dialogs.wait.progress)
	
	//-- Methods -----//
	
	$scope.getProgress = function(){
		return {'width': $scope.progress + '%'};
	}; // end getProgress
}]); // end WaitDialogCtrl

/**
 * Notify Dialog Controller 
 */
ctrlrs.controller('notifyDialogCtrl',['$scope','$modalInstance','$translate','data',function($scope,$modalInstance,$translate,data){
	//-- Variables -----//

	$scope.header = (angular.isDefined(data.header)) ? data.header : $translate.instant('DIALOGS_NOTIFICATION');
	$scope.msg = (angular.isDefined(data.msg)) ? data.msg : $translate.instant('DIALOGS_NOTIFICATION_MSG');
	$scope.icon = (angular.isDefined(data.fa) && angular.equals(data.fa,true)) ? 'fa fa-info' : 'glyphicon glyphicon-info-sign';

	//-- Methods -----//
	
	$scope.close = function(){
		$modalInstance.close();
		$scope.$destroy();
	}; // end close
}]); // end WaitDialogCtrl

/**
 * Confirm Dialog Controller 
 */
ctrlrs.controller('confirmDialogCtrl',['$scope','$modalInstance','$translate','data',function($scope,$modalInstance,$translate,data){
	//-- Variables -----//

	$scope.header = (angular.isDefined(data.header)) ? data.header : $translate.instant('DIALOGS_CONFIRMATION');
	$scope.msg = (angular.isDefined(data.msg)) ? data.msg : $translate.instant('DIALOGS_CONFIRMATION_MSG');
	$scope.icon = (angular.isDefined(data.fa) && angular.equals(data.fa,true)) ? 'fa fa-check' : 'glyphicon glyphicon-check';

	//-- Methods -----//
	
	$scope.no = function(){
		$modalInstance.dismiss('no');
	}; // end close
	
	$scope.yes = function(){
		$modalInstance.close('yes');
	}; // end yes
}]); // end ConfirmDialogCtrl / dialogs.controllers