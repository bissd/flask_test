from flask import Flask, current_app, Response, request
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from logging.handlers import RotatingFileHandler
import logging
import yaml
import json
import time

import dashscope
import base64
import hashlib
import os


def get_api_key():
    # API 密钥通过环境变量管理
    return os.getenv("DASHSCOPE_API_KEY")


def create_app():
    """
    Function to create the Flask app and initialize the necessary configurations.

    Returns:
    - Flask:
        The initialized Flask app.
    """

    # Load the database configuration from the config.yml file
    with open("config.yml", "r") as config_file:
        config = yaml.safe_load(config_file)
    try:
        # Set up the database connection
        from urllib.parse import quote

        password_encoded = quote(config["db"]["mysql"]["password"], safe="")
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"mysql+pymysql://{config['db']['mysql']['user']}:{password_encoded}@{config['db']['mysql']['host']}:{config['db']['mysql']['port']}/{config['db']['mysql']['dbname']}"
        )
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        app.config["REDIS_URL"] = "redis://localhost:6379/0"
    except KeyError as e:
        print(f"Error: 配置字段缺失 {e}")
        exit(1)


app = Flask(__name__)

# Set up logging
handler = RotatingFileHandler("app.log", maxBytes=10 * 1024 * 1024, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Create the Flask app
app = create_app()

db = SQLAlchemy()
redis = FlaskRedis()

db.init_app(app)

# Set up the Redis connection

redis.init_app(app)


def base64_md5(input_string):
    # 将字符串转换为字节串，因为b64encode接收字节类型数据
    byte_string = input_string.encode("utf-8")

    # 对字节串进行Base64编码
    base64_encoded = base64.b64encode(byte_string)

    # 创建md5对象
    md5_hash = hashlib.md5()

    # 更新md5对象的内容为Base64编码后的字节串
    md5_hash.update(base64_encoded)

    # 获取16进制形式的MD5摘要
    md5_hexdigest = md5_hash.hexdigest()

    return md5_hexdigest


def validate_input(input_data):
    """验证输入数据是否合法"""
    if not input_data:
        return False
    return True


def extract_request_data():
    """从请求中提取数据"""
    if request.is_json:
        return request.json
    elif request.form:
        return request.form
    else:
        return request.args


def check_sessionID(uid, uname, sessionID):
    if sessionID is None or sessionID == "":
        timestamp = time.time()
        sessionID = base64_md5(
            str({"uid": uid, "uname": uname, "timestamp": timestamp})
        )

    return sessionID


class UserToken(db.Model):
    """
    Model class for the UserToken table in the database.

    Attributes:
    - UserToken_ID: int
        The primary key for the UserToken table.
    - UserToken_UserID: int
        The User ID associated with the UserToken.
    - UserToken_Value: str
        The value of the UserToken.
    - UserToken_CheckTime: datetime
        The check time of the UserToken.
    - UserToken_CreateDate: datetime
        The creation date of the UserToken.
    - UserToken_UpdateDate: datetime
        The update date of the UserToken.
    """

    __tablename__ = "t_usertoken"

    UserToken_ID = db.Column(
        db.Integer, primary_key=True, autoincrement=True, comment="自增ID"
    )
    UserToken_UserID = db.Column(
        db.Integer, nullable=False, default=0, comment="用户ID"
    )
    UserToken_Value = db.Column(
        db.String(40), nullable=False, default="", comment="令牌凭据"
    )
    UserToken_IP = db.Column(
        db.String(15), nullable=False, default="", comment="客户端IP地址"
    )
    UserToken_ClientType = db.Column(
        db.SmallInteger,
        nullable=False,
        default=0,
        comment="客户端类型：0=移动端，1=PC端，2=APP，3=微信小程序",
    )
    UserToken_CheckTime = db.Column(
        db.Integer, nullable=False, default=0, comment="校验时间"
    )
    UserToken_CreateDate = db.Column(
        db.String(20), nullable=False, default="", comment="创建时间"
    )
    UserToken_UpdateDate = db.Column(
        db.String(20), nullable=False, default="", comment="更新时间"
    )

    @classmethod
    def is_exist_by_token(cls, value):
        """
        Class method to check if a UserToken with the given value exists in the database.

        Parameters:
        - value: str
            The value of the UserToken to check.

        Returns:
        - UserToken or None:
            Returns the UserToken object if it exists, otherwise returns None.
        """
        return cls.query.filter_by(UserToken_Value=value).first()

    @classmethod
    def get_user_id_by_value(cls, value):
        """
        Class method to get the User ID associated with the UserToken value from the database.

        Parameters:
        - value: str
            The value of the UserToken to get the User ID for.

        Returns:
        - int or None:
            Returns the User ID if it exists, otherwise returns None.
        """
        user_token = cls.query.filter_by(UserToken_Value=value).first()
        if user_token:
            return user_token.UserToken_UserID
        else:
            return None


class UserInfo(db.Model):
    """
    Model class for the UserInfo table in the database.

    Attributes:
    - User_ID: int
        The primary key for the UserInfo table.
    - User_Nickname: str
        The nickname of the user.
    """

    __tablename__ = "t_user"

    User_ID = db.Column(db.Integer, primary_key=True)
    User_Nickname = db.Column(db.String(255))

    @classmethod
    def exists_by_id(cls, user_id):
        """
        Class method to check if a UserInfo with the given User ID exists in the database.

        Parameters:
        - user_id: int
            The User ID to check.

        Returns:
        - UserInfo or None:
            Returns the UserInfo object if it exists, otherwise returns None.
        """
        return cls.query.filter_by(User_ID=user_id).first()

    @classmethod
    def get_nickname_by_id(cls, user_id):
        """
        Class method to get the nickname associated with the User ID from the database.

        Parameters:
        - user_id: int
            The User ID to get the nickname for.

        Returns:
        - str or None:
            Returns the nickname if it exists, otherwise returns None.
        """
        user_info = cls.query.filter_by(User_ID=user_id).first()
        if user_info:
            return user_info.User_Nickname
        else:
            return None


class Messages(db.Model):
    """
    Model class for the Messages table in the database.

    Attributes:
    - messages_ID: int
        The primary key for the Messages table.
    - messages_userID: int
        The User ID associated with the message.
    - messages_userName: str
        The username associated with the message.
    - messages_sessionID: str
        The session ID associated with the message.
    - messages_content: str
        The content of the message.
    - messages_contentAI: str
        The AI content of the message.
    - messages_createDate: datetime
        The creation date of the message.
    """

    __tablename__ = "t_messages"

    messages_ID = db.Column(db.Integer, primary_key=True)
    messages_userID = db.Column(db.Integer)
    messages_userName = db.Column(db.String(255))
    messages_sessionID = db.Column(db.String(255))
    messages_content = db.Column(db.String(255))
    messages_contentAI = db.Column(db.String(255))
    messages_createDate = db.Column(db.DateTime)

    @classmethod
    def store_message(cls, user_id, user_name, session_id, content, content_ai):
        """
        Class method to store a new message in the database.

        Parameters:
        - user_id: int
            The User ID associated with the message.
        - user_name: str
            The username associated with the message.
        - session_id: str
            The session ID associated with the message.
        - content: str
            The content of the message.
        - content_ai: str
            The AI content of the message.
        """
        new_message = cls(
            messages_userID=user_id,
            messages_userName=user_name,
            messages_sessionID=session_id,
            messages_content=content,
            messages_contentAI=content_ai,
        )
        db.session.add(new_message)
        db.session.commit()


class MessagesContext(db.Model):
    """
    Model class for the MessagesContext table in the database.

    Attributes:
    - context_id: int
        The primary key for the MessagesContext table.
    - user_id: int
        The User ID associated with the context.
    - user_nickname: str
        The nickname associated with the context.
    - session_id: str
        The session ID associated with the context.
    - context_content: str
        The content of the context.
    - create_at: datetime
        The creation date of the context.
    - update_at: datetime
        The update date of the context.
    - deleted: bool
        The deletion status of the context.
    """

    __tablename__ = "t_messages_context"

    context_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    user_nickname = db.Column(db.String(255))
    session_id = db.Column(db.String(255))
    context_content = db.Column(db.String(255))
    create_at = db.Column(db.DateTime)
    update_at = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean)

    @classmethod
    def store_context(cls, user_id, user_nickname, session_id, context_content):
        """
        Class method to store a new context in the database.

        Parameters:
        - user_id: int
            The User ID associated with the context.
        - user_nickname: str
            The nickname associated with the context.
        - session_id: str
            The session ID associated with the context.
        - context_content: str
            The content of the context.
        """
        new_context = cls(
            user_id=user_id,
            user_nickname=user_nickname,
            session_id=session_id,
            context_content=context_content,
        )
        db.session.add(new_context)
        db.session.commit()

    @classmethod
    def get_context_by_session_id(cls, session_id):
        """
        Class method to get the context associated with the given session ID from the database.

        Parameters:
        - session_id: str
            The session ID to get the context for.

        Returns:
        - MessagesContext or None:
            Returns the MessagesContext object if it exists, otherwise returns None.
        """
        return cls.query.filter_by(session_id=session_id).first()

    @classmethod
    def update_context_by_session_id(cls, session_id, new_context_content):
        """
        Class method to update the context associated with the given session ID in the database.

        Parameters:
        - session_id: str
            The session ID to update the context for.
        - new_context_content: str
            The new content of the context.
        """
        context = cls.query.filter_by(session_id=session_id).first()
        if context:
            context.context_content = new_context_content
            db.session.commit()

    @classmethod
    def mark_deleted_by_session_id(cls, session_id):
        """
        Class method to mark the context associated with the given session ID as deleted in the database.

        Parameters:
        - session_id: str
            The session ID to mark as deleted.
        """
        context = cls.query.filter_by(session_id=session_id).first()
        if context:
            context.deleted = True
            db.session.commit()


@app.route("/")
def index():
    """
    Route handler for the index page.

    Returns:
    - str:
        Returns a simple message.
    """
    return "Hello, World!"


@app.route("/login")
def login():
    """
    Route handler for the login page.

    Returns:
    - str:
        Returns a simple message.
    """
    user_token_value = current_app.redis.get("user_token")
    if not user_token_value:
        user_token_value = UserToken.query.first().UserToken_Value
        current_app.redis.set("user_token", user_token_value)
    return f"User token: {user_token_value}"


@app.route("/api/conversation", methods=["POST", "GET"])
# @token_required
def conversation():
    def generate(content, UID, UNickName, messages, sessionID=None, stream=True):
        if not validate_input(content):
            yield "data: " + json.dumps(
                {"code": 500, "msg": "请输入有效内容", "data": ""}
            ) + "\n\n"
            return

        try:
            response_generator = dashscope.Generation.call(
                model=dashscope.Generation.Models.qwen_turbo,
                messages=messages,
                stream=True,  # 确保这里设置为True以接收流式响应
                top_p=0.8,
                headers={"Authorization": f"Bearer {api_key}"},
            )

            # 初始化sessionID和code，以便在循环外也能正确yield
            sessionID = sessionID or ""
            code = 200

            for response in response_generator:
                if response.status_code == HTTPStatus.OK:
                    # 实时yield SSE格式的响应数据
                    rspdata = {
                        "data": response.output["text"],
                        "sessionID": sessionID,
                        "code": code,
                    }
                    yield "data: " + str(rspdata) + "\n\n"

                    time.sleep(random.choice([0, 0.1, 0, 0.1, 0, 0.2, 0]))
                else:
                    code = 501
                    rspdata = {
                        "code": code,
                        "msg": f"API call failed with code {response.code} and message {response.message}",
                        "data": None,
                    }
                    yield "data: " + str(rspdata) + "\n\n"

        except Exception as e:
            code = 501
            rspdata = {
                "code": code,
                "msg": f"An error occurred during API call: {e}",
                "data": None,
            }
            yield "data: " + str(rspdata) + "\n\n"
        finally:
            try:
                yield "data: [DONE]\n\n"
            except GeneratorExit:
                pass

    content_value = None
    sID = None

    # 尝试从JSON中获取
    if request.is_json:
        sID = request.json.get("SessionID")
        content_value = request.json.get("content")
        roleFlag = request.json.get("roleFlag")

    # 如果JSON中没有找到，尝试从表单数据中获取
    elif request.form:
        sID = request.form.get("SessionID")
        content_value = request.form.get("content")
        roleFlag = request.form.get("roleFlag")

    else:
        sID = request.args.get("SessionID")
        content_value = request.args.get("content")
        roleFlag = request.args.get("roleFlag")

    # token = request.headers.get("Authorization")
    token = "f03fc5960d64bfe9050bbf028654d67e"
    print(UserToken.is_exist_by_token(token))
    if not UserToken.is_exist_by_token(token):
        return (
            {
                "msg": "用户状态异常",
                "code": 401,
            },
            200,
            {"Content-Type": "text/json"},
        )

    UID = UserToken.get_user_id_by_value(token)
    UNickName = UserInfo.get_nickname_by_id(UID)
    print("UID", UID, "NickName", UNickName)

    if UID is None or UNickName is None:
        return (
            {
                "msg": "用户状态异常",
                "code": 401,
            },
            200,
            {"Content-Type": "text/json"},
        )

    sessionID = check_sessionID(UID, UNickName, sID)
    query_by_session_id_data = MessagesContext.get_context_by_session_id(sessionID)

    if query_by_session_id_data is None or len(query_by_session_id_data) == 0:
        # 如果数据库中没检索到该id，则视为首次
        if roleFlag is None:
            messages = [
                {
                    "role": "system",
                    "content": "尽量言简意赅，最多返回%s字" % (1000),
                },
            ]
        else:
            messages = [
                {
                    "role": "system",
                    "content": "%s" % (roleFlag),
                },
            ]
        messages.append({"role": "user", "content": content_value})
    else:
        import ast

        messages = ast.literal_eval(
            MessagesContext.get_context_content_by_session_id(sessionID)
        )
        # print("---1---", messages)
        messages.append({"role": "user", "content": content_value})
        # print("---1 append---", messages)

    if content_value is not None and content_value != "":
        response = Response(
            generate(
                content_value,
                UID,
                UNickName,
                messages,
                sessionID=sessionID,
                stream=True,
            ),
            mimetype="text/event-stream",
        )
        response.headers["Cache-Control"] = "no-cache"  # 防止缓存
        return response
    else:
        insert_messages_to_mysql(UID, UNickName, sessionID, "", "未监测到问题内容")
        return (
            {"code": 500, "msg": "未监测到问题内容", "data": ""},
            200,
            {"Content-Type": "text/json"},
        )


if __name__ == "__main__":

    # Run the app
    app.run(debug=True)
