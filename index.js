var mootools = require ('mootools'),
	util = require ('util'),
	Rbac = require('node-rbac').Rbac,
	Session = require('node-rbac').Session,
	Subject = require('node-rbac').Subject;

let Debug = require ( 'debug' )
const debug = Debug('node-express-authorization')

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
				////console.log('app.authentication.ON_AUTH');

				////console.log(err);
				////console.log(user);

				//this.user = (err) ? null : user;
				if(!err)
					this.new_session(user.username, user.role);

			}.bind(this));
		}

		this.addEvent(this.SET_SESSION, function(session){
			////console.log('---this.SET_SESSION----');
			////console.log(session.getSubject());
			////console.log(session.getRole());

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

	  var check_authorization = function(){//req, res, next
			let {req, resp, socket, next, opts, additional} = this._arguments(arguments)
			// debug('check_authorization', socket.handshake.session) //socket.handshake.session,

			let session = (socket) ? socket.handshake.session : req.session


			var isAuth = false;

			if(session.user && (!this.getSession() || (this.getSession() && (session.user.role != this.getSession().getRole().getID())) )){

				this.authorization.new_session(session.user.username, session.user.role);
			}
			// else if((!session || !session.user) && this.getSession()){
			// 	// this.removeSession()
			// }


			// process.exit(1)
			/**
			 * las OP no deben estar declaradas en la RBAC?? por que??
			 * alcanza con declarar la OP en "permissions"
			 * */
			 debug('check_authorization', session, this.getSession()) //socket.handshake.session,
			 if(!session.user || !this.getSession()){
				 this.log('authorization', 'error', 'authorization : No current session');
				 if(req){
					 // this['500'](req, resp, next, { error: 'No current session' });
					 next()
				 }
				 else{
					 socket.emit(
						 opts.path,
						 Object.merge({
							 status: 500,
							 error: 'No current session'
						 },
						 opts.params
						 )
					 )
				 }

			 }
			 else{
				 if(req){
					 try {
		 				isAuth = this.isAuthorized({ op: req.method.toLowerCase(), res: this.uuid +'_'+req.route.path})

		 				if (isAuth === false) {
		 					this['403'](req, resp, next, {
		 						error: 'You are not authorized to operation: '+req.method.toLowerCase()+
		 						', on resource: '+this.uuid +'_'+req.route.path
		 					});

		 				}
		 				else{
		 					//////console.log('authenticated');
		 					next();
		 				}

		 			}
		 			catch(e){
		 				//////console.log(e.message);
		 				this.log('authorization', 'error', 'authorization : ' + e.message);
		 				this['500'](req, resp, next, { error: e.message });
		 			}
				 }
				 else{
					 /**
					 * get last 2 args
					 * op: message (like req.method)
					 * res: resource
					 **/

					 // process.exit(1)
					 let _args = additional.slice(Math.max(additional.length - 2, 0))
					 debug('socket', opts, _args) //._query

					 try {
		 				isAuth = this.isAuthorized({ op: _args[0], res: _args[1]})
						debug('isAuth', _args, isAuth)
						// process.exit(1)

		 				if (isAuth === false) {
		 					// this['403'](req, res, next, {
		 					// 	error: 'You are not authorized to operation: '+req.method.toLowerCase()+
		 					// 	', on resource: '+this.uuid +'_'+req.route.path
		 					// });
							socket.emit(
								opts.path,
								Object.merge({
									status: 403,
			 						error: 'You are not authorized to operation: '+_args[0]+', on resource: '+_args[1]
								},
								opts.params
								)
							)

		 				}
		 				else{
		 					//////console.log('authenticated');
		 					next();
		 				}

		 			}
		 			catch(e){
		 				//////console.log(e.message);
						this.log('authorization', 'error', 'authorization : ' + e.message);
						debug('isAuth err', e, opts, additional)
		 				// this['500'](req, res, next, { error: e.message });

						socket.emit(
							opts.path,
							Object.merge({
								status: 500,
								error: e.message
							},
							opts.params
							)
						)

						// process.exit(1)

						// next()
		 			}

				 }
			 }





		};



		//implements a check_authorization function on the App, only if the App doens't implement one
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
		//console.log('---new_session----');
		//console.log(username);
		//console.log(role);

		const session = new Session(username);

		/**
		 * el problema es que la sub app no tendría que usar la "session", ya está inicializada;
		 * pero entonces como hace el "check" (isAuthorized)??
		 * a resolver; q las subapps no inicien session y cequeen contra la rbac de la APP padre;
		 * o que inicien session y tengan la RBAC del padre + la suya?? (me gusta más)
		 * */
		////console.log('--ROLE---')
		////console.log(this.getRoles());

		if(this.getRoles()[role]){
			if(
				Object.getLength(this.getRoles()[role].getSubjects()) == 0 ||
				!this.getRoles()[role].getSubjects()[username]
			){
				this.getRoles()[role].addSubject(new Subject(username))
			}

			////console.log(this.getRoles()[role].getSubjects());

			session.setRole(this.getRoles()[role]);

			session.setSubject(this.getRoles()[role].getSubjects()[username]);


			if(username !== 'anonymous' && role !== 'anonymous')
				this.fireEvent(this.NEW_SESSION, session);

			////console.log('--ROLE---')
			////console.log(session.getRole().getID());

			this.setSession(session);
		}

	},

  //express middleware
  session: function(){
		return function session(req, res, next) {

			this.fireEvent(this.SESSION);

			////console.log('req.session');
			////console.log(req.session);
			////console.log('req.user');
			////console.log(req.user);

			const username = (req.user) ? req.user.username : 'anonymous'
			const role = (req.user) ? req.user.role : 'anonymous'

			this.new_session(username, role);

			debug('express middleware session', this.getSession(), username, role)
			// process.exit(1)
			//if(req.session.passport.user && (!this.getSession() || this.getSession().getRole().getID('anonymous'))){

			//if(req.user && (!this.getSession() || this.getSession().getRole().getID('anonymous'))){

				//this.new_session(req.user.username, req.user.role);

			//}
			//else if( !req.user && !this.getSession() ){
				///*var session = new Session('anonymous');
				//session.setRole(this.getRoles()['anonymous']);
				//session.setSubject(this.getRoles()['anonymous'].getSubjects()['anonymous']);
				//this.setSession(session);*/
				//this.new_session('anonymous', 'anonymous');
			//}

			return next();
		}.bind(this);
  }
});
