from angrmanagement.daemon import handle_url


def test_open_binary():

    # open
    url = "angr://?action=open&path=/tmp/test&md5sum=00000000&headless=true"

    # jumpto
    url = "angr://?action=jumpto&addr=0x4006c6&md5=f6ad81a7f5028055d757f6eb39840708"

    # point of interests
    url = "angr://?action=commentat&addr=0x4006c6&md5=f6ad81a7f5028055d757f6eb39840708&comment=dGVzdCBjb21tZW50"

    # bughouse components
    url = "angr://?action=bughouse_component&md5=f6ad81a7f5028055d757f6eb39840708&url=http%3a%2f%2f127.0.0.1%2fapi%2ftest"
