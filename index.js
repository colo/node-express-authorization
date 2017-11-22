var mootools = require ('mootools'),
	util = require ('util'),
	Rbac = require('rbac').Rbac,
	Session = require('rbac').Session;

module.exports = new Class({
  Extends: Rbac,
  
  SESSION: 'session',
  NEW_SESSION: 'newSession',
  
  app: null,
  
  user: null,
  
  initialize: function(app, rules){
		this.app = app;
		this.parent(rules);
		
		this.extend_app(app);
		app.addEvent(app.ON_LOAD_APP, this.extend_app.bind(this));
		
		if(app.authentication){
			app.authentication.addEvent(app.authentication.ON_AUTH, function(err, user){
				console.log('app.authentication.ON_AUTH');
				
				console.log(err);
				console.log(user);
				
				//this.user = (err) ? null : user;
				if(!err)
					this.new_session(user.username, user.role);
				
			}.bind(this));
		}
		
		this.addEvent(this.SET_SESSION, function(session){
			app.log('authorization', 'info', 'authorization session: ' + util.inspect({subject: session.getSubject().getID(), role: session.getRole().getID()}));
			
			
		}.bind(this));
		
		this.addEvent(this.IS_AUTHORIZED, function(obj){
			if(obj.result != true)
			app.log('authorization', 'warn', 'authorization : ' + util.inspect(obj));
			else
			app.log('authorization', 'info', 'authorization : ' + util.inspect(obj));
		}.bind(this));
  },
  extend_app: function(app){
	
		var is_auth = function(obj){
			return this.isAuthorized(obj);
		}.bind(this);
		
		var get_session = function(){
			return this.getSession();
		}.bind(this);
		
		if(typeof(app) == 'function'){
			app.implement({
				isAuthorized: is_auth,
				getSession: get_session
			})
		}
		else{
			app['isAuthorized'] = is_auth;
			app['getSession'] = get_session;
		}
	  
	  var check_authorization = function(req, res, next){
			var isAuth = false;
			
			console.log('---check_authorization--');
			//console.log(this.app['get']);
			console.log(this.uuid);
			
			/**
			 * las OP no deben estar declaradas en la RBAC?? por que??
			 * alcanza con declarar la OP en "permissions"
			 * */
			try {
				isAuth = this.isAuthorized({ op: arguments[0].method.toLowerCase(), res: this.uuid})

				if (isAuth === false) {
					this['403'](req, res, next, {
						error: 'You are not authorized to operation: '+arguments[0].method.toLowerCase()+
						', on resource: '+this.uuid
					});
					
				}
				else{
					//console.log('authenticated');
					next();
				}

			}
			catch(e){
				//console.log(e.message);
				this.log('authorization', 'error', 'authorization : ' + e.message);
				this['500'](req, res, next, { error: e.message });
			}
			
				
		};
		
		
		
		//implements a check_authentication function on the App, only if the App doens't implement one
		if(!app.check_authorization){
			if(typeof(app) == 'function'){
				app.implement({
					check_authorization: check_authorization
				});
			}
			else{
				app['check_authorization'] = check_authorization;
			}
		}
  },
  new_session: function(username, role){
		const session = new Session(username);
		
		if(username !== 'anonymous' && role !== 'anonymous')
			this.fireEvent(this.NEW_SESSION, session);
		
		session.setRole(this.getRoles()[role]);
		
		session.setSubject(this.getRoles()[role].getSubjects()[username]);
		
		this.setSession(session);
	},
	
  //express middleware
  session: function(){
		return function session(req, res, next) {
			
			this.fireEvent(this.SESSION);
			
			console.log('req.session');
			console.log(req.session);
			console.log('req.user');
			console.log(req.user);

			
			//if(req.session.passport.user && (!this.getSession() || this.getSession().getRole().getID('anonymous'))){
			if(req.user && (!this.getSession() || this.getSession().getRole().getID('anonymous'))){
				
				this.new_session(req.user.username, req.user.role);
				
			}
			else {
				/*var session = new Session('anonymous');
				session.setRole(this.getRoles()['anonymous']);
				session.setSubject(this.getRoles()['anonymous'].getSubjects()['anonymous']);
				this.setSession(session);*/
				this.new_session('anonymous', 'anonymous');
			}
			
			return next();
		}.bind(this);
  }
});

