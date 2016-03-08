var mootools = require ('mootools'),
	util = require ('util'),
	Rbac = require('rbac').Rbac,
	Session = require('rbac').Session;

module.exports = new Class({
  Extends: Rbac,
  
  SESSION: 'session',
  NEW_SESSION: 'newSession',
  
  app: null,
  
  initialize: function(app, rules){
	this.app = app;
	this.parent(rules);
	
	app['isAuthorized'] = function(obj){
	  return this.isAuthorized(obj);
	}.bind(this);
	
	app['getSession'] = function(){
	  return this.getSession();
	}.bind(this);
	
		
	this.addEvent(this.SET_SESSION, function(session){
	  app.log('authorization', 'info', 'authorization session: ' + util.inspect({subject: session.getSubject().getID(), role: session.getRole().getID()}));
	  
	  //console.log('session.getRole');
	  //console.log(session.getRole().getID());
	  //console.log('session.getSubject');
	  //console.log(session.getSubject());
	}.bind(this));
	
	this.addEvent(this.IS_AUTHORIZED, function(obj){
	  if(obj.result != true)
		app.log('authorization', 'warn', 'authorization : ' + util.inspect(obj));
	  else
		app.log('authorization', 'info', 'authorization : ' + util.inspect(obj));
	}.bind(this));
	
	
	
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
		
// 		var session = new Session(req.session.passport.user);
		
		var session = new Session(req.user.username);
		this.fireEvent(this.NEW_SESSION, session);
		
// 		console.log('roles');
// 		console.log(this.getRoles()[req.user.role]);
		
		session.setRole(this.getRoles()[req.user.role]);
		
 		//console.log('subjects');
 		//console.log(this.getRoles()[req.user.role].getSubjects());
		
		
		
		session.setSubject(this.getRoles()[req.user.role].getSubjects()[req.user.username]);
		this.setSession(session);
	  }
	  else {
		var session = new Session('anonymous');
		session.setRole(this.getRoles()['anonymous']);
		session.setSubject(this.getRoles()['anonymous'].getSubjects()['anonymous']);
		this.setSession(session);
	  }
	  
	  return next();
	}.bind(this);
  }
});

