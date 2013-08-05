from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404, get_list_or_404
from django.http import HttpResponse
from django.core.cache import cache
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from models import Email, Theme

import logging
import re
import datetime
'''

	clean up cache to avoid collisions!
	views:
	by participant
	by theme

	navbar contingent on login
'''
# CACHE FUNCTIONS
def userlist(update = False):
	key = 'userlist'
	users = cache.get(key)
	if users is None or update:
		logging.error("participant list DB Query")
		users = User.objects.all().order_by("username")
		users = list(users)
		cache.set(key, users)
	return users

def themelist(update=False):
	key = 'themelist'
	themes = cache.get(key)
	if themes is None or update:
		logging.error("theme list DB query")
		themes = Theme.objects.all()
		themes = list(themes)
		cache.set(key, themes)
	return themes


def theme_by_title(title, update = False):
	key = title
	theme = cache.get(key)
	if theme is None or update:
		theme = get_object_or_404(Theme, title=title)
		cache.set(key, theme)
	return theme

def emails_by_theme(theme, update=False):
	key = str(theme) + "emails"
	emails = cache.get(key)
	if emails is None or update:
		logging.error(str(theme) + "email DB query")
		#theme = theme_by_title(title)
		emails = Email.objects.filter(theme=theme)
		emails = list(emails)
		cache.set(key, emails)
	return emails

def emails_by_user(user, update=False):
	key = str(user.pk)
	emails = cache.get(key)
	if emails is None or update:
		emails = Email.objects.filter(sender=user)
		emails = list(emails)
		cache.set(key, emails)
	return emails

def user_by_username(username, update=False):
	key = 'uname' + username
	user = cache.get(key)
	if user is None or update:
		user = get_object_or_404(User, username=username)
		cache.set(key, user)
	return user
## END CACHE FUNCTIONS



def index(request):
	participants = userlist()
	themes = themelist()
	# lists participants
	return render(request, "emails/index.html", {'participants': participants, 'themes': themes})

def themepage(request, theme):
	participants = userlist()
	themes = themelist()
	theme = theme_by_title(theme)
	emails = emails_by_theme(theme)
	return render(request, "emails/theme.html", {'emails': emails, 'theme': theme, 'participants': participants, 'themes': themes})

def addtheme(request):
	participants = userlist()
	themes = themelist()
	if request.method == "POST" and request.user.is_superuser:
		title = request.POST.get('title')
		description = request.POST.get('description')
		if not title or not description:
			error = "Please enter a title and a description"
			return render(request, "emails/addtheme.html", {'participants': participants, 'themes': themes, 'title': title, 'description': description, 'error': error})
		else:
			# create new theme and update caches
			theme = Theme()
			theme.title = title
			theme.description = description
			theme.save()
			themelist(True)
			theme_by_title(title, True)
			return redirect('/')
	else:
		return render(request, "emails/addtheme.html", {'participants': participants, 'themes': themes})

def add(request):
	def render_form(selected_theme="", recipient="", timesent="", subject="", body="", error=""):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/add.html", {'themes': themes, 'participants': participants,
			                                       'selected_theme': selected_theme, 'recipient': recipient, 'timesent': timesent,
			                                       'subject': subject, 'body': body, 'error': error})
	if request.method == 'POST' and request.user.is_authenticated():
		selected_theme = request.POST.get('theme')
		recipient = request.POST.get('recipient')
		timesent = request.POST.get('timesent')
		subject = request.POST.get('subject')
		body = request.POST.get('body')
		if not selected_theme or not recipient or not subject or not body:
			error = "Please complete all required fields"
			return render_form(selected_theme, recipient, timesent, subject, body, error)

		email = Email()
		email.theme = theme_by_title(selected_theme)
		email.sender = request.user
		email.recipient = recipient
		if email.time_sent:
			email.time_sent = datetime.datetime.strptime(timesent, '%Y-%m-%dT%H:%M')
		email.subject = subject
		email.body = body
		email.save()

		# update caches
		emails_by_user(request.user, True)
		emails_by_theme(email.theme, True)
		# redirect
		return redirect("/participant")

	else:
		return render_form()

def useremails(request, username):
	participants = userlist()
	themes = themelist()
	if request.user.is_authenticated():
		if username == request.user.username:
			return redirect('/participant')
		if username:
			user = user_by_username(username)
		else:
			user=request.user
			username = request.user.username
	else:
		user = user_by_username(username)

	emails = emails_by_user(user)
	return render(request, "emails/participant.html", {'emails': emails, 'user': user, 'themes': themes, 'participants': participants})



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
  return (EMAIL_RE.match(email) or email == "")

def error_check(username, password, verify=None, email=None, firstname=None):
	error = ""
	#signup specific error
	if verify is not None:
		try:
			if User.objects.get(username=username):
				error = "That username is already taken.  Please choose another."
				return error
		except:
			if password != verify:
				error = "Passwords don't match."
	if email is not None:
		if not valid_email(email):
			error = "Please enter a valid email address"
	if firstname is not None and not firstname:
		error = "Please enter your first name"
	# error: invalid username or password
	if not valid_username(username) or not valid_password(password):
		error = "Please enter a valid username and password."	
	return error


def signup(request):
	def render_form(firstname="", lastname="", email="", username="", error="", next_url="/"):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/signup.html", {'firstname': firstname, 'lastname': lastname, 'email': email, 
			'username': username, 'error': error, 'next_url': next_url, 'participants': participants, 'themes': themes})
	if (request.POST):
		firstname = request.POST.get('firstname')
		lastname = request.POST.get('lastname')
		email = request.POST.get('email')
		username = request.POST.get('username')
		password = request.POST.get('password')
		verify = request.POST.get('verify')
		next_url = request.POST.get('next_url')
		error = error_check(username, password, verify, email, firstname)
		if error:
			return render_form(firstname, lastname, email, username, error, next_url)
		#successful signup: save user, login, and redirect to welcome page
		else:
			user = User.objects.create_user(username=username, password=password)
			user.first_name=firstname
			user.last_name=lastname
			user.email=username
			user.save()
			user=authenticate(username=username, password=password)
			login(request, user)

			#update user-related caches
			user_by_username(username, True)
			userlist(True)
			return redirect(next_url)
	else:
		next_url = request.META.get('HTTP_REFERER')
		if not next_url or '/login' in next_url or '/signup' in next_url:
			next_url = "/"
		# redirect already logged-in users
		if request.user.is_authenticated():
			return redirect(next_url)
		return render_form(next_url=next_url)


def userlogin(request):
	def render_form(username="", error="", next_url="/"):
		participants = userlist()
		themes = themelist()
		return render(request, "emails/login.html", {'username': username, 'error': error, 'next_url': next_url, 
			'participants': participants, 'themes': themes})
	if (request.POST):
		username = request.POST.get('username')
		password = request.POST.get('password')
		next_url = request.POST.get('next_url')
		error = error_check(username, password)
		if error:
			return render_form(username, error, next_url)
		else:
			user = authenticate(username=username, password=password)
			if user is not None:
				login(request, user)
				return redirect(next_url)
			else:
				error = "Please enter a valid username and password."
				return render_form(username, error, next_url)
	else:
		next_url = request.META.get('HTTP_REFERER')
		if not next_url or '/login' in next_url or '/signup' in next_url:
			next_url = "/"
		# redirect already logged-in users
		if request.user.is_authenticated():
			return redirect(next_url)
		return render_form(next_url=next_url)

def userlogout(request):
	next_url = request.META.get('HTTP_REFERER')
	if not next_url:
		next_url = "/"
	logout(request)
	return redirect(next_url)
def about(request):
	participants = userlist()
	themes = themelist()
	return render(request, "emails/about.html", {'participants': participants, 'themes': themes})

