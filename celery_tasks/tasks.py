from django.conf import settings
from django.core.mail import send_mail
# 导入Celery类
from celery import Celery

# 这两行代码需要的启动worker 的一端打开
# 初始化django所依赖的环境
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dailyfresh.settings")

# 创建一个Celery类的对象
app = Celery('celery_tasks.tasks', broker='redis://127.0.0.1:6379/5')


# 定义任务函数
@app.task
def send_register_active_email(to_email, username, token):
    """发送激活邮件"""
    # 组织邮件内容
    subject = '天天生鲜欢迎信息'
    message = ''
    sender = settings.EMAIL_FROM
    print(sender)
    receiver = [to_email]
    html_message = '<h1>%s, 欢迎您成为天天生鲜注册会员</h1>请点击以下链接激活您的账户<br/><a href="http://127.0.0.1:8000/user/active/%s">http://127.0.0.1:8000/user/active/%s</a>' % (
        username, token, token)

    # 给用户的注册邮箱发送激活邮件，激活邮件中需要包含激活链接：/user/active/用户id
    # /user/active/token
    send_mail(subject, message, sender, receiver, html_message=html_message)
