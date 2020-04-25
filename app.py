import secrets
import os
import datetime
from PIL import Image
from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
'''from forms import RegistrationForm, LoginForm'''

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

from flask_bcrypt import Bcrypt
from flask_mail import Mail,Message



app = Flask(__name__)


app.config['SECRET_KEY']= '8d2c6184ae40cc9efdefe76c746248dd'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///rakaar.db'
app.config.update(
    DEBUG=True,
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,

    )
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view = ('login')
login_manager.login_message_category = 'info'
mail = Mail(app)
'''from models import User'''

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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


class Discussion(db.Model):
    '''
    DB model for bug discussion
    '''
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String, nullable=False)
    project_id = db.Column(db.String, nullable=False)
    bug_title = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    date_time = db.Column(db.String, nullable=False)
class Bug(db.Model):
    '''
    DB model for BUGS
    '''
    id = db.Column(db.Integer, primary_key=True)
    project_id=db.Column(db.String, nullable=False)
    title = db.Column(db.String(20), unique=True, nullable=False)
    date_reported = db.Column(db.String, nullable=False)
    last_modified = db.Column(db.String, nullable=False)
    reportee = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String, nullable=False)
    reproducible = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    severity = db.Column(db.String, nullable=False)
    assignees = db.Column(db.String, nullable=True)
    discussion = db.Column(db.String, nullable=True)

class Project(db.Model):
    '''
    DB model for PROJECTS
    '''
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)
    started_on = db.Column(db.String, nullable=False)
    last_modified = db.Column(db.String, nullable=False)
    managers = db.Column(db.String, nullable=False)
    owner =  db.Column(db.String, nullable=False)
    bugs = db.Column(db.String, nullable=True) 
    

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/about")
def about():
    return render_template('about.html' , title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    '''
    Sign Up for BugTracker
    '''
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        joined_name = "-".join(form.name.data.split(" "))
        user=User(username=form.username.data, name=joined_name, email=form.email.data, password=hashed_password, phone=form.phone.data, tiep=form.tiep.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!','success')
        return redirect(url_for('login'))
    return render_template('register.html' , title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    '''
    Login for Alum Portal
    '''
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful!!!Incorrect Email or Password')
    return render_template('login.html', title='Login', form=form)



@app.route("/logout")
def logout():
    """
    Logout for BugTracker
    """
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    
    i = Image.open(form_picture)
    
    i.save(picture_path)
    return picture_fn

@app.route("/update_bug/<int:bug_id>", methods=['GET', 'POST'])
@login_required
def update_bug(bug_id):
    all_bugs = Bug.query.all()
    if bug_id > len(all_bugs):
        abort(404)
    bug = Bug.query.get(bug_id)
    all_users = User.query.all()
    current_assignees = ''
    current_assignees_list = []
    for user in all_users:
        if user.username in bug.assignees.split(","):
            current_assignees_list.append(user.username + '@' + user.name)
    current_assignees = ','.join(current_assignees_list)
    if request.method == "GET":
        print(bug.status)
        return render_template('update_bug.html', bug=bug, users=all_users, current_assignees=current_assignees)
    elif request.method == 'POST':
        print("I GOT THE POST REQUEST")
        bug.title = request.form.get("title")
        bug.description = request.form.get("description")
        bug.reproducible = request.form.get("reproducible").lower()
        bug.status = request.form.get("status").lower()
        bug.severity = request.form.get("severity").lower()
        complex_assignees = request.form.get("assignees")
        complex_assignees_list = complex_assignees.split(",")
        assignees_usernames = []
        for cmplx_ass in complex_assignees_list:
            cmplx_ass_list = cmplx_ass.split("@")
            ass_username = cmplx_ass_list[0]
            if ass_username not in assignees_usernames:
                assignees_usernames.append(ass_username)
        assignees = ",".join(assignees_usernames)
        bug.assignees = assignees
        last_modified = datetime.datetime.now()
        bug.last_modified = last_modified.strftime("%d") + " " + last_modified.strftime("%B") + " " + last_modified.strftime("%Y") 
        db.session.commit()
        return redirect(url_for('bug', project_id = int(bug.project_id), bug_title = bug.title))
        


@app.route("/update_project/<int:project_id>", methods=['GET', 'POST'])
@login_required
def update_project(project_id):
    project = Project.query.get(project_id)
    all_users = User.query.all()
    current_managers = ''
    current_managers_list = []
    for user in all_users:
        if user.username in project.managers.split(","):
            current_managers_list.append(user.username + '@' + user.name)
    current_managers = ','.join(current_managers_list)
    if request.method == "GET":
        return render_template('update_project.html', project=project, users=all_users, current_managers=current_managers)
    elif request.method == "POST":
        print("I GOT THE POST REQUEST")
        project.title = request.form.get("title")
        project.description = request.form.get("description")
        complex_managers = request.form.get("managers")
        complex_managers_list = complex_managers.split(",")
        managers_usernames = []
        for cmplx_man in complex_managers_list:
            cmplx_man_list = cmplx_man.split("@")
            man_username = cmplx_man_list[0]
            if man_username not in managers_usernames:
                managers_usernames.append(man_username)
        managers = ",".join(managers_usernames)
        project.managers = managers
        last_modified = datetime.datetime.now()
        project.last_modified = last_modified.strftime("%d") + " " + last_modified.strftime("%B") + " " + last_modified.strftime("%Y") 
        db.session.commit()
        return redirect(url_for('project', project_id = project_id))


@app.route("/bug/<int:project_id>/<bug_title>", methods=['GET', 'POST'])
def bug(project_id, bug_title):
    bugs = Bug.query.all()
    required_bug = "new variable"
    for bug in bugs:
        if int(bug.project_id) == project_id and bug.title == bug_title:
            required_bug = bug
            break
    if(type(required_bug) == str):
        abort(404)
    
    discussion = required_bug.discussion
    discussion_id_list = []
    if discussion != None:
        discussion_id_list = discussion.split(",")
    
    discussions = Discussion.query.all()

    discussion_list = []
    for disc in discussions:
        if str(disc.id) in discussion_id_list:
            discussion_list.append(disc)
    if request.method == "GET":
        return render_template('bug.html', bug=required_bug, discussion=discussion_list)
    elif request.method == 'POST':
        comment = request.form.get("comment")
        new_disc = Discussion(user = current_user.username, project_id = project_id , bug_title=required_bug.title, content=comment , date_time= str(datetime.datetime.now())[:-7])
        db.session.add(new_disc)
        discussion_list.append(new_disc)
        
        new_disc_id = len(discussions) +1
        if discussion != None:
            required_bug.discussion = discussion + "," + str(new_disc_id)
        else:
            required_bug.discussion = str(new_disc_id)
        db.session.commit()
        return render_template('bug.html', bug=required_bug, discussion=discussion_list)

@app.route("/project/id/<int:project_id>", methods=['GET', 'POST'])
def project(project_id):
    bugs = Bug.query.all()
    project_bugs = []
    for bug in bugs:
        if int(bug.project_id) == project_id:
            project_bugs.append(bug)
    project = Project.query.get(project_id)
    return render_template('project.html', project=project, project_bugs=project_bugs)

@app.route("/my_bugs", methods=['GET', 'POST'])
@login_required
def my_bugs():
    all_bugs = Bug.query.all()
    assigned_bugs = []
    reported_bugs = []
    for a_bug in all_bugs:
        if a_bug.assignees != None and current_user.username in a_bug.assignees.split(","):
            assigned_bugs.append(a_bug)
        if current_user.username == a_bug.reportee:
            reported_bugs.append(a_bug)
    return render_template('my_bugs.html', assigned_bugs=assigned_bugs, reported_bugs=reported_bugs)

@app.route("/my_projects", methods=['GET', 'POST'])
@login_required
def my_projects():
    all_projects = Project.query.all()
    all_bugs = Bug.query.all()
    projects = []
    for a_project in all_projects:
        if current_user.username == a_project.owner or  current_user.username in a_project.managers.split(","):
            projects.append(a_project)
    for a_bug in all_bugs:
        if current_user.username == a_bug.reportee or current_user.username in a_bug.assignees.split(","):
            bugs_project = Project.query.get(int(a_bug.project_id))
            if bugs_project not in projects:
                projects.append(bugs_project)

    return render_template('my_projects.html', projects=projects, all_bugs=all_bugs)


@app.route("/explore", methods=['GET', 'POST'])
def explore():
    all_projects = Project.query.all()
    all_bugs = Bug.query.all()
    return render_template('my_projects.html', projects=all_projects, all_bugs=all_bugs)

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UpdateAccountForm()
    if request.method=="POST":
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('dashboard'))
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('dashboard.html', title='Dashboard', image_file=image_file, form=form, user=current_user)

@app.route("/update_profile", methods=['GET', 'POST'])
@login_required
def update_profile():
    user = current_user
    if request.method =="GET":
        return render_template('update_profile.html', user=user)
    elif request.method =="POST":
        current_user.name = request.form.get("name")
        current_user.email = request.form.get("email")
        current_user.phone = request.form.get("phone")
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('dashboard'))



@app.route("/new_project", methods=['GET', 'POST'])
@login_required
def new_project():
    '''
    Start New Project 
    '''
    
    form = NewProjectForm()
    
    # render the complaint template on get request in browser
    print('request.method = ', request.method)
    if request.method ==  "GET":
        print('in get')
        return render_template('new_project.html', form=form)

    # on form submission, a POST request is made which sends the mail
    elif request.method == 'POST':
        if form.validate_on_submit():
            title = form.title.data
            description = form.description.data
            creator = current_user.username
            last_modified = datetime.datetime.now()
            last_modified = last_modified.strftime("%d") + " " + last_modified.strftime("%B") + " " + last_modified.strftime("%Y") 
            started_on = last_modified
            project=Project(title=title, description=description, last_modified=last_modified, managers=creator, owner=creator, started_on=started_on )
            db.session.add(project)
            db.session.commit()
            flash(f'Project created for {current_user.username}!','success')
            projects=Project.query.all()
            project_id=len(projects)
            return redirect(url_for('project',project_id=project_id))

@app.route("/report_bug/<int:project_id>", methods=['GET', 'POST'])
@login_required
def report_bug(project_id):
    '''
    Report Bug
    '''
    
    form = ReportBugForm()
    if request.method ==  "GET":
        return render_template('report_bug.html', form=form)

    # on form submission, a POST request is made which sends the mail
    elif request.method == 'POST':
        if form.validate_on_submit():
            title = form.title.data
            description = form.description.data
            reproducible = form.reproducible.raw_data[0].lower() # member this for SelectField objects
            reportee = current_user.username
            last_modified = datetime.datetime.now()
            last_modified = last_modified.strftime("%d") + " " + last_modified.strftime("%B") + " " + last_modified.strftime("%Y") 
            bug=Bug(project_id=project_id, title=title, description=description, last_modified=last_modified, reproducible=reproducible, reportee=reportee, date_reported=last_modified, severity="unknown", status="unknown")
            db.session.add(bug)
            db.session.commit()
            flash(f'Bug reported by {current_user.username}!','success')
            return redirect(url_for('bug',project_id=project_id, bug_title=title))







class RegistrationForm(FlaskForm):
    username=StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    name=StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
    email=StringField('Email', validators=[DataRequired(), Email()])
    password=PasswordField('Password', validators=[DataRequired()])
    confirm_password=PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone=StringField('Phone', validators=[DataRequired(), Length(min=10, max=10)])
    tiep=SelectField('Type', choices=[('dev', 'Developer'), ('man', 'Manager')])
    submit=SubmitField('Sign Up')

    def validate_username(self, username):
        user=User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exist')

    def validate_email(self, email):
        user=User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exist')



class UpdateAccountForm(FlaskForm):
    picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit=SubmitField('Update Profile Pic')

    


class ComplaintForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    room = StringField('Room Number', validators=[DataRequired()])
    complaint = StringField('Complaint', validators=[DataRequired()])
    submit=SubmitField('Submit Complaint')

class LoginForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(), Email()])
    password=PasswordField('Password', validators=[DataRequired()])
    remember=BooleanField('Remember Me')
    submit=SubmitField('Login')


class ReportBugForm(FlaskForm):
    title=StringField('Title', validators=[DataRequired()])
    description=StringField('Bug Description', validators=[DataRequired()])
    reproducible=SelectField('Is the Bug Reproducible ?', choices=[('unknown', "Don't Know"), ('yes', 'YES'), ('no', 'NO')])
    submit=SubmitField('Report Bug')

class NewProjectForm(FlaskForm):
    title=StringField('Title', validators=[DataRequired()])
    description=StringField('Describe your project here', validators=[DataRequired()])
    submit=SubmitField('Create Project')

class UpdateBugForm(FlaskForm):
    title=StringField('Title', validators=[DataRequired()])
    description=StringField('Bug Description', validators=[DataRequired()])
    reproducible=SelectField('Is the Bug Reproducible ?', choices=[('yes', 'YES'), ('no', 'NO'), ('unknown', "Don't Know")])
    status=SelectField('Status', choices=[('resolved', 'Resolved'), ('new', 'New'), ('unknown', 'Unknown'), ('verified', 'Verified'), ('processing', 'In Progress')])
    severity=SelectField('Priority', choices=[('unknown', 'Unknown'), ('high', 'High'), ('low', 'Low'), ('regular','Regular')])
    assignees=StringField('Assignees', validators=[])
    submit=SubmitField('Update Bug')

class UpdateProjectForm(FlaskForm):
    title=SelectField('Title', validators=[DataRequired])
    description=StringField('Describe your project here', validators=[DataRequired()])
    managers=StringField('Project Managers', validators=[DataRequired()])
    submit=SubmitField('Update Project')
if __name__ =='__main__':
    app.run(debug=True)

