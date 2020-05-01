from flask import Flask, render_template, request, redirect, logging, make_response, json
from ethw3 import genkey, create_chain_data, verify_chain_data, create_acct, mine, history_slice
from utils_s3 import load_from_fetchlist

# Initialize flask an other global variables
app = Flask(__name__)
address, username, addr, priv, contVer, web3Ver = None,None,None,None,None,None
sig = []
txHash = []
status,status2 = 0,0
recordDict, matchedData = {}, {}
entryList = []

@app.route('/')
def render_index():
    mine()
    recordDict, history = load_from_fetchlist(history=True)
    history = history_slice(history, 20)
    global address, sig, txHash, username, status, contVer, web3Ver, addr, priv, status2, matchedData
    _sig, _address, _txHash, _username, _status, _contVer, _web3Ver, _addr, _priv, _status2, _matchedData = sig, address, txHash, username, status, contVer, web3Ver, addr, priv, status2, matchedData
    address, username, contVer, web3Ver, addr, priv = tuple([None]*6)
    sig, txHash = [], []
    status, status2 = 0,0
    matchedData = {}
    return render_template("index.html",
                           entryList = recordDict,
                           history = history,
                           txhash = _txHash,
                           address = _addr,
                           username = _username,
                           sig=_sig,
                           privkey=_priv,
                           showStatus = _status,
                           web3Ver = _web3Ver,
                           contVer = _contVer,
                           status2 = _status2,
                           matchedData = _matchedData)

@app.route('/submit', methods=['POST'])
def hash_to_chain():
    global sig, txHash, username, address
    sig, address, txHash, username = None,None,None,None
    test = 'check' in request.form
    fsFile = request.files["file"].read()
    pkey = request.form.get("pkey")
    username = request.form.get("name")
    cookie_value = create_acct(pkey).address
    if username == "":
        username = "Anonymous"
    username, sig, address, txHash = create_chain_data(fsFile, pkey, username, test)
    resp = make_response(redirect('/', code=302))
    resp.set_cookie("ID", cookie_value, max_age=60*1)
    return resp

@app.route("/verify", methods=["POST"])
def verify_from_chain():
    global status, contVer, web3Ver
    status, contVer, web3Ver = None,None,None
    test = 'check2' in request.form
    print(test)
    fsFile = request.files["file"].read()
    sig = request.form.get("sig")
    if fsFile == b'':
        web3Ver = "nofile"
        status = 0
        return redirect("/", code=302)
    status, contVer, web3Ver = verify_chain_data(fsFile, sig, test)
    return redirect("/", code=302)

@app.route('/generate', methods=['POST', "GET"])
def generatekeypair():
    global addr, priv
    addr, priv = genkey()
    return redirect("/", code=302)

@app.route("/whosigned", methods=["POST"])
def direct_verify():
    global status2, contVer, matchedData
    status, contVer = None,None
    test = 'check3' in request.form
    sig = request.form.get("sig")
    status2, contVer, matchedData= verify_chain_data(sig=sig, test=test)
    return redirect("/", code=302)


if __name__ == '__main__':
   app.run(debug=True)
   gunicorn_logger = logging.getLogger('gunicorn.error')
   app.logger.handlers = gunicorn_logger.handlers
   app.logger.setLevel(gunicorn_logger.level)
