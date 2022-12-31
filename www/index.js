import init, {encrypt, decrypt} from "../pkg/wasm_cipher.js";
init().then(() => {
    window.encrypt = encrypt;
    window.decrypt = decrypt;
}) ;

const q = (query) => {
    return document.querySelector(query);
}

function enc_on() {
    //console.log(q("#inbox"));
    q("#outbox").value = window.encrypt(q("#password").value, q("#inbox").value) ;
}

function swap_on() {
    q("#inbox").value = q("#outbox").value;
    q("#outbox").value = "";
}

function dec_on() {
    //console.log(q("#inbox"));
    q("#outbox").value = window.decrypt(q("#password").value, q("#inbox").value) ;
}

function resizer(element) {
    element.target.style.height = 0;
    element.target.style.height = element.target.scrollHeight + "px";
}

function resize_textarea() {
    const box_in = q("#inbox");
    box_in.addEventListener("click", e => { resizer(e) }, false);
    box_in.addEventListener("keydown", e => { resizer(e) }, false);

    const box_out = q("#outbox");
    box_out.addEventListener("click", e => { resizer(e) }, false);
    box_out.addEventListener("keydown", e => { resizer(e) }, false);
}

const main = () => {
    window.onload = () => {
        q("#inbox").style.height = q("#inbox").scrollHeight + "px";
        q("#outbox").style.height = q("#outbox").scrollHeight + "px";
    }

    resize_textarea();

    const clipboard = new Clipboard(".copy-value");
    clipboard.on("success", e => {
        if (q("#outbox").value != "") { alert("Copied!") };
        e.clearSelection();
    }, false);

    addEventListener("click", e => {
        if (e.target.getAttribute("id") == "encrypt") {
            enc_on();
        } else if (e.target.getAttribute("id") == "decrypt") {
            dec_on();
        } else if (e.target.getAttribute("id") == "swap") {
            swap_on();
        }
    }, false);
};

main();
