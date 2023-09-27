# -*- coding: utf-8 -*-
# @Author  : liuqi
# @Time    : 2023/9/27 14:15
# @Function:
def test_json_transport():
    json_k = ["nonce", "header", "ciphertext", "tag"]
    json_v = ["CSIJ+e8KP7HJo+hC4RXIyQ==", "aGVhZGVy", "9YYjuAn6", "kXHrs9ZwYmjDkmfEJx7Clg=="]
    res = zip(json_k, json_v)
    assert dict(res) == {'nonce': 'CSIJ+e8KP7HJo+hC4RXIyQ==', 'header': 'aGVhZGVy', 'ciphertext': '9YYjuAn6',
                         'tag': 'kXHrs9ZwYmjDkmfEJx7Clg=='}