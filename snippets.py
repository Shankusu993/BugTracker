class User(db.Model, UserMixin):
    '''
    DB model for USERS
    '''
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(20), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	image_file = db.Column(db.String(), nullable=False, default='default.jpg')
	password = db.Column(db.String(60), nullable=False)
	phone = db.Column(db.String(10), nullable=False)
    tiep = db.Column(db.String, nullable=False)
	def __repr__(self):
		return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Bug(db.Model):
    '''
    DB model for BUGS
    '''
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), unique=True, nullabl=False)
    date_reported = db.Column(db.String, nullable=False)
    last_modified = db.Column(db.String, nullable=False)
    reportee = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String, nullable=False)
    reproducible = db.Column(db.String, nullable=True)
    status = db.Column(db.String, nullable=False)
    severity = db.Coolumn(db.String, nullable=False)
    assignees = db.Column(db.String, nullable=False)

class Project(db.Model):
    '''
    DB model for PROJECTS
    '''
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), unique=True, nullabl=False)
    description = db.Column(db.String, nullable=False)
    last_modified = db.Column(db.String, nullable=False)
    managers = db.Column(db.String, nullable=False) 
    bugs = db.Column(db.String, nullable=False) 
    


# Projects
# 
# 
# <div class="jumbotron bg-dark text-info p-2">
#     <h1 class="display-3 title text-center">Another Ambit</h1>
    
#     <div class="d-flex">
#         <div class="p-2 text-info"><h4 class="title"><u>Top Issues</u></h4></div>
#         <div class="ml-auto p-2"><a class="btn btn-outline-info" href="#" role="button">Go to Project</a></div>
#     </div>
#     <div class="d-flex">
#         <div class="p-2 text-info"><h5 class="title">Bug 1 Title</h5></div>
#         <div class="ml-auto p-2"><a class="btn btn-outline-info" href="#" role="button">Go to Bug</a></div>
#     </div>
#     <div class="d-flex">
#         <div class="p-2 text-info"><h5 class="title">Bug 2 Title</h5></div>
#         <div class="ml-auto p-2"><a class="btn btn-outline-info" href="#" role="button">Go to Bug</a></div>
#     </div>
#  </div> 
