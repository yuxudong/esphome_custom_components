# ESPHOME的external components
---
## xiaomi_lock
小米智能门锁的状态，需要mac地址和bindkey，具体获得方法请访问bbs.hassbian.com  
yaml格式：
```
external_components:
  - source:
      type: git
      url: https://github.com/yuxudong/esphome_custom_components
    components: [ xiaomi_lock ]
sensor:
  - platform: xiaomi_lock
    id: dongshan
    mac_address: 'xx:xx:xx:xx:xx:xx'
    bindkey: '000102030405060708090a0b0c0d0e0f'
    lockevt:
    lockevtts:
    doorevt:
    doorevtts:
    battlvl:
    battlvlts:
    bioevt:
    keyid:
```
    
