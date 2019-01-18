# wxpay
微信支付 Python SDK
对微信支付开发者文档中给出的API进行了封装。WXPay类下提供了对应的方法：

方法名	说明
micropay	刷卡支付
unifiedorder	统一下单
orderquery	查询订单
reverse	撤销订单
closeorder	关闭订单
refund	申请退款
refundquery	查询退款
downloadbill	下载对账单
report	交易保障
shorturl	转换短链接
authcodetoopenid	授权码查询openid
参数为dict类型，返回类型也是dict。 方法内部会将参数会转换成含有appid、mch_id、nonce_str和sign的XML； 通过HTTPS请求得到返回数据后会对其做必要的处理（例如验证签名，签名错误则抛出异常）。

对于downloadbill，无论是否成功都返回dict类型对象，且都含有return_code和return_msg。 若成功，其中return_code为SUCCESS，另外data对应对账单数据。

兼容性
在Python2.7.6和Python 3.4.3中测试通过。

安装
方式1：

$ sudo pip install -r requirements.txt
$ sudo python setup.py install
方式2:

$ sudo pip install pywxpay
Python 3使用pip3、python3命令安装。
