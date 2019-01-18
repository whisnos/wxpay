# coding: utf-8
# wxpay sdk
# Author: www.debug5.com

import hashlib
import hmac
import copy
import uuid
import requests
import sys

import xml.etree.ElementTree as ElementTree

try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except:
    pass

PY2 = sys.version_info[0] == 2
if not PY2:
    # Python 3.x and up
    text_type = str
    string_types = (str,)
    xrange = range


    def as_text(v):  ## 生成unicode字符串
        if v is None:
            return None
        elif isinstance(v, bytes):
            return v.decode('utf-8', errors='ignore')
        elif isinstance(v, str):
            return v
        else:
            raise ValueError('Unknown type %r' % type(v))


    def is_text(v):
        return isinstance(v, text_type)

else:
    # Python 2.x
    text_type = unicode
    string_types = (str, unicode)
    xrange = xrange


    def as_text(v):
        if v is None:
            return None
        elif isinstance(v, unicode):
            return v
        elif isinstance(v, str):
            return v.decode('utf-8', errors='ignore')
        else:
            raise ValueError('Invalid type %r' % type(v))


    def is_text(v):
        return isinstance(v, text_type)

_DEFAULT_TIMEOUT = 8000  # 微秒


class WXPayConstants(object):
    # SUCCESS, FAIL
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"

    # 签名类型
    SIGN_TYPE_HMACSHA256 = "HMAC-SHA256"
    SIGN_TYPE_MD5 = "MD5"

    # 字段
    FIELD_SIGN = "sign"
    FIELD_SIGN_TYPE = "sign_type"

    # URL
    MICROPAY_URL = "https://api.mch.weixin.qq.com/pay/micropay"
    UNIFIEDORDER_URL = "https://api.mch.weixin.qq.com/pay/unifiedorder"
    ORDERQUERY_URL = "https://api.mch.weixin.qq.com/pay/orderquery"
    REVERSE_URL = "https://api.mch.weixin.qq.com/secapi/pay/reverse"
    CLOSEORDER_URL = "https://api.mch.weixin.qq.com/pay/closeorder"
    REFUND_URL = "https://api.mch.weixin.qq.com/secapi/pay/refund"
    REFUNDQUERY_URL = "https://api.mch.weixin.qq.com/pay/refundquery"
    DOWNLOADBILL_URL = "https://api.mch.weixin.qq.com/pay/downloadbill"
    REPORT_URL = "https://api.mch.weixin.qq.com/payitil/report"
    SHORTURL_URL = "https://api.mch.weixin.qq.com/tools/shorturl"
    AUTHCODETOOPENID_URL = "https://api.mch.weixin.qq.com/tools/authcodetoopenid"

    # Sandbox URL
    SANDBOX_MICROPAY_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/micropay"
    SANDBOX_UNIFIEDORDER_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/unifiedorder"
    SANDBOX_ORDERQUERY_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/orderquery"
    SANDBOX_REVERSE_URL = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/reverse"
    SANDBOX_CLOSEORDER_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/closeorder"
    SANDBOX_REFUND_URL = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/refund"
    SANDBOX_REFUNDQUERY_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/refundquery"
    SANDBOX_DOWNLOADBILL_URL = "https://api.mch.weixin.qq.com/sandboxnew/pay/downloadbill"
    SANDBOX_REPORT_URL = "https://api.mch.weixin.qq.com/sandboxnew/payitil/report"
    SANDBOX_SHORTURL_URL = "https://api.mch.weixin.qq.com/sandboxnew/tools/shorturl"
    SANDBOX_AUTHCODETOOPENID_URL = "https://api.mch.weixin.qq.com/sandboxnew/tools/authcodetoopenid"


class WXPayUtil(object):

    @staticmethod
    def dict2xml(data):
        """dict to xml

        @:param data: Dictionary
        @:return: string
        """
        # return as_text( xmltodict.unparse({'xml': data_dict}, pretty=True) )
        root = ElementTree.Element('xml')
        for k in data:
            v = data[k]
            child = ElementTree.SubElement(root, k)
            child.text = str(v)
        return as_text(ElementTree.tostring(root, encoding='utf-8'))

    @staticmethod
    def xml2dict(xml_str):
        """xml to dict

        @:param xml_str: string in XML format
        @:return: Dictionary
        """
        # return xmltodict.parse(xml_str)['xml']
        root = ElementTree.fromstring(xml_str)
        assert as_text(root.tag) == as_text('xml')
        result = {}
        for child in root:
            tag = child.tag
            text = child.text
            result[tag] = text
        return result

    @staticmethod
    def generate_signature(data, key, sign_type=WXPayConstants.SIGN_TYPE_MD5):
        """生成签名

        :param data: dict
        :param key: string. API key
        :param sign_type: string
        :return string
        """
        key = as_text(key)
        data_key_list = data.keys()
        data_key_list = sorted(data_key_list)  # 排序！
        combine_str = as_text('')
        for k in data_key_list:
            v = data[k]
            if k == WXPayConstants.FIELD_SIGN:
                continue
            if v is None or len(str(v)) == 0:
                continue
            combine_str = combine_str + as_text(str(k)) + as_text('=') + as_text(str(v)) + as_text('&')
        combine_str = combine_str + as_text('key=') + key
        if sign_type == WXPayConstants.SIGN_TYPE_MD5:
            return WXPayUtil.md5(combine_str)
        elif sign_type == WXPayConstants.SIGN_TYPE_HMACSHA256:
            return WXPayUtil.hmacsha256(combine_str, key)
        else:
            raise Exception("Invalid sign_type: {}".format(sign_type))

    @staticmethod
    def is_signature_valid(data, key, sign_type=WXPayConstants.SIGN_TYPE_MD5):
        """ 验证xml中的签名

        :param data: dict
        :param key: string. API key
        :param sign_type: string
        :return: bool
        """
        if WXPayConstants.FIELD_SIGN not in data:
            return False
        sign = WXPayUtil.generate_signature(data, key, sign_type)
        if sign == data[WXPayConstants.FIELD_SIGN]:
            return True
        return False

    @staticmethod
    def generate_signed_xml(data, key, sign_type=WXPayConstants.SIGN_TYPE_MD5):
        """ 生成带有签名的xml

        :param data: dict
        :param key: string. API key
        :param sign_type: string
        :return: xml
        """
        key = as_text(key)
        new_data_dict = copy.deepcopy(data)
        sign = WXPayUtil.generate_signature(data, key, sign_type)
        new_data_dict[WXPayConstants.FIELD_SIGN] = sign
        return WXPayUtil.dict2xml(new_data_dict)

    @staticmethod
    def generate_nonce_str():
        """ 生成随机字符串

        :return string
        """
        r = uuid.uuid1().hex.replace('-', '')
        return as_text(r)

    @staticmethod
    def md5(source):
        """ generate md5 of source. the result is Uppercase and Hexdigest.

        @:param source: string
        @:return: string
        """
        hash_md5 = hashlib.md5(as_text(source).encode('utf-8'))
        return hash_md5.hexdigest().upper()

    @staticmethod
    def hmacsha256(source, key):
        """ generate hmacsha256 of source. the result is Uppercase and Hexdigest.

        @:param source: string
        @:param key: string
        @:return: string
        """
        return hmac.new(as_text(key).encode('utf-8'), as_text(source).encode('utf-8'),
                        hashlib.sha256).hexdigest().upper()


class SignInvalidException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class WXPay(object):

    def __init__(self, app_id, mch_id, key, cert_pem_path, key_pem_path, timeout=_DEFAULT_TIMEOUT,
                 sign_type=WXPayConstants.SIGN_TYPE_MD5, use_sandbox=False, plat_type=None):
        """ 初始化

        :param timeout: 网络请求超时时间，单位毫秒
        """
        self.app_id = app_id
        self.mch_id = mch_id
        self.key = key
        self.cert_pem_path = cert_pem_path
        self.key_pem_path = key_pem_path
        self.timeout = timeout
        self.sign_type = sign_type
        self.use_sandbox = use_sandbox
        self.plat_type = plat_type

    def fill_request_data(self, data):
        """data中添加 appid、mch_id、nonce_str、sign_type、sign

        :param data: dict
        :return: dict
        """
        new_data_dict = copy.deepcopy(data)
        new_data_dict['appid'] = self.app_id
        new_data_dict['mch_id'] = self.mch_id
        new_data_dict['nonce_str'] = WXPayUtil.generate_nonce_str()
        if self.plat_type == '1':
            new_data_dict = scene_info
        if self.sign_type == WXPayConstants.SIGN_TYPE_MD5:
            new_data_dict['sign_type'] = WXPayConstants.SIGN_TYPE_MD5
        elif self.sign_type == WXPayConstants.SIGN_TYPE_HMACSHA256:
            new_data_dict['sign_type'] = WXPayConstants.SIGN_TYPE_HMACSHA256
        else:
            raise Exception("Invalid sign_type: {}".format(self.sign_type))

        new_data_dict['sign'] = WXPayUtil.generate_signature(new_data_dict, self.key, self.sign_type)
        return new_data_dict

    def is_response_signature_valid(self, data):
        """检查微信响应的xml数据中签名是否合法，先转换成dict

        :param data: dict类型
        :return: bool
        """
        return WXPayUtil.is_signature_valid(data, self.key, self.sign_type)

    def is_pay_result_notify_signature_valid(self, data):
        """支付结果通知中的签名是否合法

        :param data: dict
        :return: bool
        """
        sign_type = data.get(WXPayConstants.FIELD_SIGN, WXPayConstants.SIGN_TYPE_MD5)
        if len(sign_type.trim()) == 0:
            sign_type = WXPayConstants.SIGN_TYPE_MD5
        if sign_type not in [WXPayConstants.SIGN_TYPE_MD5, WXPayConstants.SIGN_TYPE_HMACSHA256]:
            raise Exception("invalid sign_type: {} in pay result notify".format(sign_type))
        return WXPayUtil.is_signature_valid(data, self.key, sign_type)

    def request_with_cert(self, url, data, timeout=None):
        """ """
        req_body = WXPayUtil.dict2xml(data).encode('utf-8')
        req_headers = {'Content-Type': 'application/xml'}
        _timeout = self.timeout if timeout is None else timeout
        resp = requests.post(url,
                             data=req_body,
                             headers=req_headers,
                             timeout=_timeout / 1000.0,
                             cert=(self.cert_pem_path, self.key_pem_path),
                             verify=True)
        resp.encoding = 'utf-8'
        return resp.text

        # if resp.status_code == 200:
        #     # print as_text(resp.text)
        #     return as_text(resp.text)
        # raise Exception('HTTP response code is not 200')

    def request_without_cert(self, url, data, timeout=None):
        """ 不带证书的请求

        :param url: string
        :param data: dict
        :param timeout: int. ms
        :return:
        """
        req_body = WXPayUtil.dict2xml(data).encode('utf-8')
        req_headers = {'Content-Type': 'application/xml'}
        _timeout = self.timeout if timeout is None else timeout
        resp = requests.post(url,
                             data=req_body,
                             headers=req_headers,
                             timeout=_timeout / 1000.0)
        resp.encoding = 'utf-8'
        return as_text(resp.text)

        # if resp.status_code == 200:
        #     # print as_text(resp.text)
        #     return as_text(resp.text)
        # raise Exception('HTTP response code is not 200')

    def process_response_xml(self, resp_xml):
        """ 处理微信支付返回的 xml 格式数据

        :param resp_xml:
        :return:
        """
        resp_dict = WXPayUtil.xml2dict(resp_xml)
        if 'return_code' in resp_dict:
            return_code = resp_dict.get('return_code')
        else:
            raise Exception('no return_code in response data: {}'.format(resp_xml))

        if return_code == WXPayConstants.FAIL:
            return resp_dict
        elif return_code == WXPayConstants.SUCCESS:
            if self.is_response_signature_valid(resp_dict):
                return resp_dict
            else:
                raise SignInvalidException('invalid sign in response data: {}'.format(resp_xml))
        else:
            raise Exception('return_code value {} is invalid in response data: {}'.format(return_code, resp_xml))

    def micropay(self, data, timeout=None):
        """ 提交刷卡支付

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_MICROPAY_URL
        else:
            url = WXPayConstants.MICROPAY_URL

        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def unifiedorder(self, data, timeout=None):
        """ 统一下单

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_UNIFIEDORDER_URL
        else:
            url = WXPayConstants.UNIFIEDORDER_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def orderquery(self, data, timeout=None):
        """ 查询订单

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_ORDERQUERY_URL
        else:
            url = WXPayConstants.ORDERQUERY_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def reverse(self, data, timeout=None):
        """ 撤销订单

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_REVERSE_URL
        else:
            url = WXPayConstants.REVERSE_URL
        resp_xml = self.request_with_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def closeorder(self, data, timeout=None):
        """ 关闭订单

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_CLOSEORDER_URL
        else:
            url = WXPayConstants.CLOSEORDER_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def refund(self, data, timeout=None):
        """ 申请退款

        :param data: dict
        :param timeout: int
        :return: dict
        """
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_REFUND_URL
        else:
            url = WXPayConstants.REFUND_URL
        _timeout = self.timeout if timeout is None else timeout
        resp_xml = self.request_with_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def refundquery(self, data, timeout=None):
        """ 查询退款

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_REFUNDQUERY_URL
        else:
            url = WXPayConstants.REFUNDQUERY_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def downloadbill(self, data, timeout=None):
        """ 下载对账单。官方文档中指出成功时返回对账单数据，失败时返回XML格式数据。
        这里做一层封装，都返回dict。

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_DOWNLOADBILL_URL
        else:
            url = WXPayConstants.DOWNLOADBILL_URL
        resp = self.request_without_cert(url, self.fill_request_data(data), _timeout).strip()
        if resp.startswith('<'):  # 是XML，下载出错了
            resp_dict = WXPayUtil.xml2dict(resp)
        else:  # 下载成功，加一层封装
            resp_dict = {'return_code': 'SUCCESS', 'return_msg': '', 'data': resp}
        return resp_dict

    def report(self, data, timeout=None):
        """ 交易保障

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_REPORT_URL
        else:
            url = WXPayConstants.REPORT_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        resp_dict = WXPayUtil.xml2dict(resp_xml)
        return resp_dict

    def shorturl(self, data, timeout=None):
        """ 转换短链接

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_SHORTURL_URL
        else:
            url = WXPayConstants.SHORTURL_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)

    def authcodetoopenid(self, data, timeout=None):
        """ 授权码查询OPENID接口

        :param data: dict
        :param timeout: int
        :return: dict
        """
        _timeout = self.timeout if timeout is None else timeout
        if self.use_sandbox:
            url = WXPayConstants.SANDBOX_AUTHCODETOOPENID_URL
        else:
            url = WXPayConstants.AUTHCODETOOPENID_URL
        resp_xml = self.request_without_cert(url, self.fill_request_data(data), _timeout)
        return self.process_response_xml(resp_xml)
