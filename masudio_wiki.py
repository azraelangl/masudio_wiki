import os
import webapp2
import jinja2
import hmac
import re
import random
import hashlib
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def add_wiki_revision(path, content):
	last_revised_wiki = Wiki.all().filter('path = ', path).order('-revision').get()
	if last_revised_wiki is None:
		wiki = Wiki(path = path, content = content, revision = 1)
	else:
		revision = last_revised_wiki.revision + 1
		wiki = Wiki(path = path, content = content, revision = revision)

	wiki.put()

SECRET = 'imsosecret'
def hash_str(s):
        return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	if h is None:
		return None

        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val

def make_salt():
        return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
        if not salt:
                salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
        salt = h.split(',')[1]
        if make_pw_hash(name, pw, salt) == h:
                return True
        else:  
                return False

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)

class Wiki(db.Model):
	path = db.StringProperty(required = True)
	revision = db.IntegerProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainPage(Handler):
	def get(self):
		self.write("<h2>Welcome to masudio's wiki!</h2>")

class Welcome(Handler):
        def get(self):
		username = self.request.cookies.get("username")
		username = check_secure_val(username)
		if username:
			self.render("welcome.html", username = username)
		else:
			self.redirect("/wiki/signup")

class WikiPage(Handler):
	def get(self, path):
		wiki = Wiki.all().filter("path =", path).order("-revision")
		wiki = wiki.get()
		username = self.request.cookies.get("username")
		username = check_secure_val(username)
		if wiki:
			if username:
				link = "out"
			else:
				link = "in"

			self.render("wiki_page.html", wiki = wiki, link = link)
		else:
			if username:
				add_wiki_revision(path, 'Enter content here')
			else:
				add_wiki_revision(path, 'Enter content here')
				
			self.redirect("/wiki/_edit" + path)

class EditPage(Handler):
	def get(self, path):
		username = self.request.cookies.get("username")
		username = check_secure_val(username)
		if username:
			wiki = Wiki.all().filter("path =", path).order("-revision")
			wiki = wiki.get()
			if wiki:
				self.render("edit_wiki_page.html", wiki = wiki)
			else:
				self.error(404)
		else:
			self.redirect("/wiki/signup")

	def post(self, path):
		content = self.request.get("content")
		wiki = Wiki.all().filter("path =", path).order("-revision")
		wiki = wiki.get()
		if wiki:
			add_wiki_revision(path, content)

		self.redirect("/wiki" + path)

class HistoryPage(Handler):
	def get(self, path):
		username = self.request.cookies.get("username")
		username = check_secure_val(username)
		if username:
			link = "out"
		else:
			link = "in"

		revisions = Wiki.all().filter("path =", path).order("-revision")
		self.render("history_wiki_page.html", revisions = revisions, path = path, link = link)

class LogIn(Handler):
        def get(self):
                self.render("login.html", username = "")

        def post(self):
                given_username = self.request.get("username")
                given_password = self.request.get("password")
                user = User.gql("WHERE username = '" + given_username + "'")
		user = user.get()
                if user and valid_pw(given_username, given_password, user.password):
                        secure_username = make_secure_val(self.request.get("username"))
                        self.response.headers.add_header("Set-Cookie", str("username=" + secure_username + "; Path=/"))
                        self.redirect('/wiki/welcome')
                else:  
                        self.render("login.html", username = given_username)

class LogOut(Handler):
        def get(self):
                username = self.request.cookies.get("username")
                secure_username = make_secure_val(username)
                self.response.headers.add_header("Set-Cookie", str("username=; Path=/;"))
                self.redirect('/wiki/login')

class SignUp(Handler):
        def get(self):
		self.render("sign_up_page.html", given_username="",
						username_error = "",
						password_error = "",
						verify_error ="",
						given_email = "",
						email_error = "")

        def post(self):
                input_valid = True
		given_username = self.request.get("username")
		given_password = self.request.get("password")
		given_email = self.request.get("email")

                username_error = ""
                password_error = ""
                verify_error = ""
                email_error = ""

                if not self.username_valid(given_username):
                        input_valid = False
                        username_error = "That's not a valid username."
                if not self.password_valid():
                        input_valid = False
                        password_error = "That's not a valid password."
                if not self.passwords_match():
                        input_valid = False
                        verify_error = "Passwords don't match."
                if not self.email_valid(given_email):
                        input_valid = False
                        email_error = "That's not a valid email."

                if input_valid:
			password = make_pw_hash(given_username, given_password)
			user = User(username = given_username, password = password, email = given_email)
			user.put()

			secure_username= make_secure_val(self.request.get("username"))
			self.response.headers.add_header("Set-Cookie", str("username=" + secure_username + "; Path=/"))
                        self.redirect("/wiki/welcome")
                else:
			self.render("sign_up_page.html", given_username = self.request.get("username"),
							username_error = username_error,
							password_error = password_error,
							verify_error =verify_error,
							given_email = self.request.get("email"),
							email_error = email_error)

        def username_valid(self, given_username):
                USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
                is_valid = USER_RE.match(self.request.get("username"))
		matching_usernames = User.gql("WHERE username = '" + given_username + "' LIMIT 1")
		is_distinct = (0 == matching_usernames.count())
		return is_valid and is_distinct

        def password_valid(self):
                PASSWORD_RE = re.compile(r"^.{3,20}$")
                return PASSWORD_RE.match(self.request.get("password"))

        def passwords_match(self):
                return self.request.get("password") == self.request.get("verify")

        def email_valid(self, given_email):
		if not given_email:
			return True
                EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
                is_valid = EMAIL_RE.match(self.request.get("email"))
		matching_emails = User.gql("WHERE email = '" + given_email + "' LIMIT 1")
		is_distinct = (0 == matching_emails.count())
		return is_valid and is_distinct

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/wiki', MainPage),
				('/wiki/signup', SignUp),
				('/wiki/welcome', Welcome),
				('/wiki/login', LogIn),
				('/wiki/logout', LogOut),
				('/wiki/_edit' + PAGE_RE, EditPage),
				('/wiki/_history' + PAGE_RE, HistoryPage),
				('/wiki' + PAGE_RE, WikiPage)],
                              debug=True)
