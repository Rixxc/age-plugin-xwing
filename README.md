# age-plugin-xwing

`age-plugin-xwing` is a plugin for [age](https://age-encryption.org/v1)
clients like [`age`](https://age-encryption.org) and [`rage`](https://str4d.xyz/rage),
which enables files to be encrypted using the pre/post-quantum hybrid KEM [X-Wing](https://x-wi.ng).

## Disclaimer ⚠️

This software has **not** undergone any independent security audit.
In particular, the implementation of the [X-Wing KEM](https://docs.rs/x-wing/latest/x_wing/)
has not been independently audited.

USE AT YOUR OWN RISK!

## Installation

| Environment | CLI command |
|-------------|-------------|
| Cargo       | `cargo install age-plugin-xwing` |

## Usage

A key can be generated by executing the plugin binary `age-plugin-xwing`.

```sh
$ age-plugin-xwing | tee age_x_wing.key
# created: 1970-01-01T00:00:00+00:00
# recipient: age1xwing1jfdy5fhryzmfg6y89dka6xr2wup9favgprpq0x542yg43wa9xc4tfxrk8zvhp0e6cu8whfskhzszxh0cv4h850y4lsyj8sm327q4ssqkqp9vynauf3zlz23npfdt68lpj789en9m9wzaqjjt4aph053t8t2s2y24rg2nz7peteuhvhlnt3vsqf8cdw8ed2qr29zs6jfxpnk5wu8x9paqz3uhsztmf6u9vzjt2fc4ad08mw9mfarjyf5n29llj64yscuuddycyfv6waw8jgzz8t3k3w684uu7dhgtuqhv4ru25hunzx8fp5q0pxwra6cxfhu4yewmlzs8esywh298cqutqzlxt30g6fqsw52t4cgv5dl8qjzwcyfdkqq65ty4stsn6078w94ms0fsz9amk5mvqtekj9mt9ly4pdqqrjefxj6j2hj8nwxh9czu4vsw98xlgem96jvcg7quq6jydfpx6629vsjduddch3ef96cr3wus3vgjm97qwvcsk8yjr6e6dnd9gvrg24ck2dcpv9esrm472kmpudyrxuurwspn36veymghxjqvzfmfuytpxrj6tp5rdw4pzq4jh0rgga3rsdkv83jucc0zk3a6dyetklzcvwzxqk73yg0c5zyf0qnhdcnnld2gdqshy2q7d9qmsa0dfjus6guhg0mk8u3y48qy93ux8s78g3ytlyy8q2vzxgwk0w25c3mj76gscg8z9tv0q2nuhtyqf2dsj93mawx4jazwkagftf88g64f435549asksenvjsew2xu7wp386qnx2yqp7flfn4kvematxpt8a5mecyfqqzkkhrpcx6dx7t68k3vxw7efuzmjzygag0mwemcnxevlu0ygpfd4f9f56snsyey09ammmgpvm0zz4ky49ldjq6rcgyqnlpufjghpjnfwfjmm4jttu5t07suhqg4zp84hxad3qgz2rmv5jx8850tvf4ukf84uk5xz5cc4vs44naxpqzj0w6uacj0zwu5w0fmpemw5k4met99xdz04gmu5tcnkkn6qavcsqavcyfkd3f3kywyw53sk4as0jnjzxfzmqajvnt44kgj5ac9g449yykq2lkpdp394tpn0fx0vq2aass7w5zgls7zd58lswqcjzsldcmx5lcvrg6gxj08yvlem2dd8cp56wr2un0yefv2dpes2kll4xga7j4sr6ecntu34xvalv82wca83umqwp2nts60se7765j86qax5g99zajpg8eytwkd690g0djgu569hu0nd8y9gj6dzsshaxuy4nfx3p5ysfwjkfe7rj8gw4r7vvn875d6vvmmpw0wgyuadfn5645glzxv9mqs5u4jex8ya6zy8dw9x35u2yuer8ez7e73knxdshn4zw62xy804qy56qlvak4ppjz3fhmh9r02ndqxqpmraf2kd9dhtcq85sq6njl4mgqzx6a5p4mxn9w5yxlys2qcv58rmp7wzmvcenx29v23wrq5zjls7wmr26j59fyztht4pj67e3tpcmrj9ftq3yc88u90qwsczdtgyjcvccr547suvja6ya3jjevk05g9znqupxj2cyy60ztjs2snj9czf6sq5aw334jn3fp4cwng5qrjmtxqcwmxj3hu9t2xyfcvvcmcc2rz6kqzhtkev7e0qlx2jez6gw2cya6ydp59hf8vu7e9rl9x7gs4gzyrxnygxmvxzccl9ud6wn3zs0c2ft9rsdzspvw352xzvhze05sr9jn2nxvhfssm8a5knxv2z4gmvezrs6truy4mwwuta5qnl86crm9qyynz74lmn9ge22spgukhnk2qhva9av0xyjxt625wjfuzl4sxftmz5umf3dxpuqccs0m5575m08h6h5lw8nlntqpn68dz25fjym2pg8w8k3lkr0r6za9d0u67t56gjmv435gd0594f5q9
AGE-PLUGIN-XWING-14MQLVR89VVT5T9DGDZDJ2RCXQGF9N0D96RG2UXNEQL9TLN8R3JAQC3HX69
```

Once the plugin is installed,
the standard `age` client can be used to encrypt and decrypt files.

Encryption:

```sh
echo 'It works!' | age -e -r age1xwing1jfdy5fhryzmfg6y89dka6xr2wup9favgprpq0x542yg43wa9xc4tfxrk8zvhp0e6cu8whfskhzszxh0cv4h850y4lsyj8sm327q4ssqkqp9vynauf3zlz23npfdt68lpj789en9m9wzaqjjt4aph053t8t2s2y24rg2nz7peteuhvhlnt3vsqf8cdw8ed2qr29zs6jfxpnk5wu8x9paqz3uhsztmf6u9vzjt2fc4ad08mw9mfarjyf5n29llj64yscuuddycyfv6waw8jgzz8t3k3w684uu7dhgtuqhv4ru25hunzx8fp5q0pxwra6cxfhu4yewmlzs8esywh298cqutqzlxt30g6fqsw52t4cgv5dl8qjzwcyfdkqq65ty4stsn6078w94ms0fsz9amk5mvqtekj9mt9ly4pdqqrjefxj6j2hj8nwxh9czu4vsw98xlgem96jvcg7quq6jydfpx6629vsjduddch3ef96cr3wus3vgjm97qwvcsk8yjr6e6dnd9gvrg24ck2dcpv9esrm472kmpudyrxuurwspn36veymghxjqvzfmfuytpxrj6tp5rdw4pzq4jh0rgga3rsdkv83jucc0zk3a6dyetklzcvwzxqk73yg0c5zyf0qnhdcnnld2gdqshy2q7d9qmsa0dfjus6guhg0mk8u3y48qy93ux8s78g3ytlyy8q2vzxgwk0w25c3mj76gscg8z9tv0q2nuhtyqf2dsj93mawx4jazwkagftf88g64f435549asksenvjsew2xu7wp386qnx2yqp7flfn4kvematxpt8a5mecyfqqzkkhrpcx6dx7t68k3vxw7efuzmjzygag0mwemcnxevlu0ygpfd4f9f56snsyey09ammmgpvm0zz4ky49ldjq6rcgyqnlpufjghpjnfwfjmm4jttu5t07suhqg4zp84hxad3qgz2rmv5jx8850tvf4ukf84uk5xz5cc4vs44naxpqzj0w6uacj0zwu5w0fmpemw5k4met99xdz04gmu5tcnkkn6qavcsqavcyfkd3f3kywyw53sk4as0jnjzxfzmqajvnt44kgj5ac9g449yykq2lkpdp394tpn0fx0vq2aass7w5zgls7zd58lswqcjzsldcmx5lcvrg6gxj08yvlem2dd8cp56wr2un0yefv2dpes2kll4xga7j4sr6ecntu34xvalv82wca83umqwp2nts60se7765j86qax5g99zajpg8eytwkd690g0djgu569hu0nd8y9gj6dzsshaxuy4nfx3p5ysfwjkfe7rj8gw4r7vvn875d6vvmmpw0wgyuadfn5645glzxv9mqs5u4jex8ya6zy8dw9x35u2yuer8ez7e73knxdshn4zw62xy804qy56qlvak4ppjz3fhmh9r02ndqxqpmraf2kd9dhtcq85sq6njl4mgqzx6a5p4mxn9w5yxlys2qcv58rmp7wzmvcenx29v23wrq5zjls7wmr26j59fyztht4pj67e3tpcmrj9ftq3yc88u90qwsczdtgyjcvccr547suvja6ya3jjevk05g9znqupxj2cyy60ztjs2snj9czf6sq5aw334jn3fp4cwng5qrjmtxqcwmxj3hu9t2xyfcvvcmcc2rz6kqzhtkev7e0qlx2jez6gw2cya6ydp59hf8vu7e9rl9x7gs4gzyrxnygxmvxzccl9ud6wn3zs0c2ft9rsdzspvw352xzvhze05sr9jn2nxvhfssm8a5knxv2z4gmvezrs6truy4mwwuta5qnl86crm9qyynz74lmn9ge22spgukhnk2qhva9av0xyjxt625wjfuzl4sxftmz5umf3dxpuqccs0m5575m08h6h5lw8nlntqpn68dz25fjym2pg8w8k3lkr0r6za9d0u67t56gjmv435gd0594f5q9 -o secret.enc
```

Decryption:

```sh
$ age -d -i x_wing_key.txt secret.enc
It works!
```
