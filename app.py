import datetime
import json
import os
import re

import tornado.concurrent
import tornado.gen
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.process
import tornado.web

from tornado.options import define, options
from tornado.web import URLSpec as URL

from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    DateTimeField,
    IntegrityError,
    TextField,
    BooleanField
)

from password import PBKDF2PasswordManager, Password

STREAM = tornado.process.Subprocess.STREAM

define("port", default=5000, help="run on the given port", type=int)
define("db_file", help="destination for sqlite file", type=str)

if __name__ == "__main__":
    tornado.options.parse_command_line()

print(options.db_file)

# Note: database.transaction, atomic and execution context
# should not be used in asynchronous code as there is a threal-local
# transaction and execution context queue in peewee.
database = SqliteDatabase(options.db_file)

password_manager = PBKDF2PasswordManager()


class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    username = CharField(unique=True)
    password = CharField()
    join_date = DateTimeField()

    class Meta:
        order_by = ('username',)


class PingTask(BaseModel):
    output = TextField(default='')
    is_finished = BooleanField(default=False)
    start_time = DateTimeField()
    end_time = DateTimeField(null=True)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            URL(r'/', IndexHandler, name='index'),
            URL(r'/register', RegisterHandler, name='register'),
            URL(r'/login', LoginHandler, name='login'),
            URL(r'/logout', LogoutHandler, name='logout'),
            URL(r'/query', QueryHandler, name='query'),
            URL(r'/math', MathHandler, name='math'),
            URL(r'/ping', PingHandler, name='ping'),
            URL(r'/ping/_wait', PingWatcherRequest, name='wait_ping'),
        ]

        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/login",
            debug=True,
        )

        super(Application, self).__init__(handlers, **settings)

        self.db = database

        self.maybe_create_tables()

    def maybe_create_tables(self):
        self.db.create_tables([User, PingTask], safe=True)


class BaseRequestHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user = self.get_secure_cookie('uid')
        if not user:
            return
        try:
            user = int(user)
        except ValueError:
            return
        try:
            return User.get(User.id == user)
        except User.DoesNotExist:
            return

    @property
    def db(self):
        return self.application.db

    def data_received(self, chunk):
        return super(BaseRequestHandler, self).data_received(chunk)


class IndexHandler(BaseRequestHandler):
    def get(self):
        return self.render('index.html')


class RegisterHandler(BaseRequestHandler):
    context = dict(
        username='',
        no_username=False,
        wrong_username=False,
        big_username=False,
        miss_pass=False,
        weak_pass=False,
        strong_pass=False,
        already_has=False
    )

    def post(self, ):
        context = self.context.copy()

        username = self.get_body_argument('username', '')
        password1 = self.get_body_argument('password1', '')
        password2 = self.get_body_argument('password2', '')

        if not username:
            self.set_status(400)
            context.update(dict(no_username=True))
            return self.render('register.html', **context)
        elif re.match(r'^[-_\w]+$', username) is None:
            self.set_status(400)
            context.update(dict(wrong_username=True))
            return self.render('register.html', **context)
        elif len(username) > 15:
            self.set_status(400)
            context.update(dict(big_username=True))
            return self.render('register.html', **context)
        elif password1 != password2:
            self.set_status(400)
            context.update(dict(miss_pass=True))
            return self.render('register.html', **context)
        elif not password1:
            self.set_status(400)
            context.update(dict(weak_pass=True))
            return self.render('register.html', **context)
        elif len(password1) > 15:
            self.set_status(400)
            context.update(dict(strong_pass=True))
            return self.render('register.html', **context)

        password = password_manager.make_password(password1).to_string()
        try:
            user = User.create(
                username=username,
                password=password,
                join_date=datetime.datetime.now()
            )
        except IntegrityError:
            self.set_status(400)
            context.update(dict(already_has=True))
            return self.render('register.html', **context)
        else:
            self.set_secure_cookie('uid', str(user.id))
            return self.redirect(self.reverse_url('index'))

    def get(self):
        return self.render('register.html', **self.context)


class LoginHandler(BaseRequestHandler):
    def post(self):
        next_url = self.get_query_argument('next', None)

        username = self.get_body_argument('username', '')
        password = self.get_body_argument('password', '')

        try:
            user = User.get(username=username)

            user_password = password
            password = Password.from_string(user.password)

            if password_manager.check_password(user_password, password):
                self.set_secure_cookie('uid', str(user.id))
                return self.redirect(next_url or self.reverse_url('index'))
        except User.DoesNotExist:
            pass

        self.set_status(400)
        return self.render('login.html', username=username, incorrect=True)

    def get(self):
        return self.render('login.html', username='', incorrect=False)


class LogoutHandler(BaseRequestHandler):
    def get(self):
        self.set_secure_cookie('uid', '')
        return self.redirect(self.reverse_url('index'))


class QueryHandler(BaseRequestHandler):
    @tornado.web.authenticated
    def post(self):
        query = self.get_body_argument('query')

        try:
            data = self.db.execute_sql(query)
            result = 'SUCCESS:\n\n{}'.format('\n'.join(map(repr, data)))
        except Exception as e:
            result = 'ERROR:\n\n{}'.format(e)

        return self.render('query_result.html', result=result)

    @tornado.web.authenticated
    def get(self):
        return self.render('query.html')


class MathHandler(BaseRequestHandler):
    @tornado.web.authenticated
    def post(self):
        n = number = self.get_body_argument('number')

        try:
            number = int(number) * 1.0
        except ValueError:
            return self.send_error(400)

        numbers = {}
        i = 2

        while number > 1:
            if not number % i:
                number //= i
                numbers[i] = 1 + numbers.get(i, 0)
            else:
                i += 1

        numbers = sorted(numbers.items())

        return self.render('math_result.html', numbers=numbers, n=n)

    @tornado.web.authenticated
    def get(self):
        return self.render('math.html')


class PingHandler(BaseRequestHandler):
    class ProcessWatcher:
        def __init__(self, subprocess, ping_task):
            self._ping_task = ping_task
            self._lines = ''
            self._len_flushed = 0
            self._subprocess = subprocess

            self._timer = tornado.ioloop.PeriodicCallback(
                self._update, 1000, io_loop=self._subprocess.io_loop
            )

            self._timer.start()

            subprocess.io_loop.spawn_callback(self._read)

            self._future = tornado.concurrent.Future()

            self.is_finished = False

        def wait_for_event(self):
            return self._future

        async def _read(self):
            while not self._subprocess.stdout.closed():
                try:
                    line = await self._subprocess.stdout.read_until(b'\n')
                except tornado.iostream.StreamClosedError:
                    break
                self._lines += line.decode('ascii')
                self._future.set_result(self._lines)
                self._future = tornado.concurrent.Future()

            code = await self._subprocess.wait_for_exit(raise_error=False)
            self._timer.stop()
            self._lines += '\n\n---\nProcess finished with code {}'.format(code)
            self._update(finished=True)
            self.is_finished = True

            PingHandler.unregister_task(self._ping_task.id)

            self._future.set_result(self._lines)

        def _update(self, finished=False):
            if finished or len(self._lines) > self._len_flushed:
                self._ping_task.output = self._lines
                if finished:
                    self._ping_task.is_finished = finished
                    self._ping_task.end_time = datetime.datetime.now()
                self._ping_task.save()
                self._len_flushed = len(self._lines)

    @tornado.web.authenticated
    def get(self):
        return self.render('ping.html', ip=self.request.remote_ip)

    @tornado.web.authenticated
    def post(self):
        ping_task = PingTask.create(start_time=datetime.datetime.now())

        ip = self.get_body_argument('ip', self.request.remote_ip)
        command = 'ping -c 10 \'{}\''.format(ip)
        subprocess = tornado.process.Subprocess(
            command, stdout=STREAM, shell=True
        )

        self.register_task(
            ping_task.id,
            self.ProcessWatcher(subprocess, ping_task)
        )

        self.render('ping_result.html', task_id=ping_task.id)

    _tasks = {}

    @classmethod
    def register_task(cls, task_id, task):
        cls._tasks[task_id] = task

    @classmethod
    def unregister_task(cls, task_id):
        cls._tasks.pop(task_id, None)

    @classmethod
    def get_task(cls, task_id):
        return cls._tasks.get(task_id)


class PingWatcherRequest(BaseRequestHandler):
    @tornado.web.authenticated
    async def get(self):
        task_id = self.get_argument('task_id')
        if not task_id:
            return self.send_error(400)
        try:
            task_id = int(task_id)
        except ValueError:
            return self.send_error(400)

        process_watcher = PingHandler.get_task(task_id)
        if process_watcher is None:
            try:
                ping_task = PingTask.get(PingTask.id == task_id)
            except PingTask.DoesNotExist:
                return self.send_error(404)

            lines = ping_task.output
            is_finished = ping_task.is_finished

            if not is_finished:
                await tornado.gen.sleep(0.5)
        else:
            lines = await process_watcher.wait_for_event()
            is_finished = process_watcher.is_finished

        self.write(
            json.dumps({
                'lines': lines,
                'is_finished': is_finished
            })
        )


def main():
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
