use futures::{Future, Stream};
use hawk::{Credentials, Key, PayloadHasher, RequestBuilder, SHA256};
use hyper;
use hyper::{header, Client, Method, Request};
use hyper_hawk::{HawkScheme, ServerAuthorization};
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tokio_core::reactor::Core;
use url::Url;

fn start_node_server() -> (Child, u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", 0)).unwrap();
    let callback_port = listener.local_addr().unwrap().port();

    // check for `node_modules' first
    let path = Path::new("tests/node/node_modules");
    if !path.is_dir() {
        panic!(
            "Run `yarn` or `npm install` in tests/node, or test with --features \
             no-interoperability"
        );
    }

    let child = Command::new("node")
        .arg("serve-one.js")
        .arg(format!("{}", callback_port))
        .current_dir("tests/node")
        .spawn()
        .expect("node command failed to start");

    // wait until the process is ready, signalled by a connect to the callback port, and then
    // return the port it provides. We know this will only get one connection, but iteration
    // is easier anyway
    #[cfg_attr(feature = "cargo-clippy", allow(never_loop))]
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        let mut data: Vec<u8> = vec![];
        stream.read_to_end(&mut data).unwrap();
        let port = u16::from_str(std::str::from_utf8(&data).unwrap()).unwrap();

        drop(stream);
        return (child, port);
    }
    unreachable!();
}

fn make_credentials() -> Credentials {
    Credentials {
        id: "dh37fgj492je".to_string(),
        key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", &SHA256),
    }
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_header() {
    let (mut child, port) = start_node_server();

    let credentials = make_credentials();
    let url = Url::parse(&format!("http://localhost:{}/rệsource", port)).unwrap();
    let body = "foo=bar";

    // build a hawk::Request
    let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_bytes());
    let hawk_req = RequestBuilder::from_url("POST", &url)
        .unwrap()
        .hash(&payload_hash[..])
        .ext("ext-content")
        .request();

    // build a hyper::Request
    let mut req = Request::new(Method::Post, url.as_str().parse().unwrap());
    let req_header = hawk_req.make_header(&credentials).unwrap();
    req.headers_mut()
        .set(header::Authorization(HawkScheme(req_header.clone())));
    req.headers_mut().set(header::ContentType::plaintext());
    req.set_body(body);
    println!("{:?}", req);

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let client = Client::new(&handle);
    let work = client
        .request(req)
        .and_then(|res| {
            assert_eq!(res.status(), hyper::Ok);
            let server_hdr = res
                .headers()
                .get::<ServerAuthorization<HawkScheme>>()
                .unwrap()
                .clone();
            res.body().concat2().map(|body| (body, server_hdr))
        })
        .map(|(body, server_hdr)| {
            // check we got the expected body
            assert_eq!(body.as_ref(), b"Hello Steve ext-content");

            // validate server's signature
            let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_ref());
            let response = hawk_req
                .make_response_builder(&req_header)
                .hash(&payload_hash[..])
                .response();
            if !response.validate_header(&server_hdr, &credentials.key) {
                panic!("authentication of response header failed");
            }
        });

    core.run(work).unwrap();

    // drop everything to allow the client connection to close and thus the Node server
    // to exit.  Curiously, just dropping client is not sufficient - the core holds the
    // socket open.
    drop(client);
    drop(handle);
    drop(core);

    child.wait().expect("Failure waiting for child");
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_bewit() {
    let (mut child, port) = start_node_server();

    let credentials = make_credentials();
    let url = Url::parse(&format!("http://localhost:{}/rệsource", port)).unwrap();
    let hawk_req = RequestBuilder::from_url("GET", &url)
        .unwrap()
        .ext("ext-content")
        .request();

    let bewit = hawk_req
        .make_bewit(&credentials, SystemTime::now() + Duration::from_secs(60))
        .unwrap();
    let mut url = url.clone();
    url.set_query(Some(&format!("bewit={}", bewit.to_str())));

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let client = Client::new(&handle);
    let work = client.get(url.as_str().parse().unwrap()).and_then(|res| {
        assert_eq!(res.status(), hyper::Ok);

        res.body().concat2().map(|body| {
            assert_eq!(body.as_ref(), b"Hello Steve ext-content");
        })
    });

    core.run(work).unwrap();

    // drop everything to allow the client connection to close and thus the Node server
    // to exit.  Curiously, just dropping client is not sufficient - the core holds the
    // socket open.
    drop(client);
    drop(handle);
    drop(core);

    child.wait().expect("Failure waiting for child");
}
