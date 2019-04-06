use futures::stream::Concat2;
use futures::{Async, Future, Poll, Stream};
use hawk::{Bewit, Credentials, Key, PayloadHasher, RequestBuilder, SHA256};
use hyper;
use hyper::header::{Authorization, ContentLength};
use hyper::server::{Http, Service};
use hyper::{Body, Client, Method, Request, Response};
use hyper_hawk::{HawkScheme, ServerAuthorization};
use std::borrow::Cow;
use std::time::Duration;
use url::Url;

// It's impossible to have Service::Future be a Map type with a closure, because it is unsigned. Or
// looked at another way, async Rust is still in its infancy.  So we define a custom Future which
// can gather the request body and validate the request.

struct ServerHeaderValidatorFuture {
    header: Option<Authorization<HawkScheme>>,
    require_hash: bool,
    send_hash: bool,
    body_stream: Concat2<Body>,
}

impl Future for ServerHeaderValidatorFuture {
    type Item = Response;
    type Error = hyper::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body_stream.poll() {
            Ok(Async::Ready(body)) => {
                // build a request object based on what we know
                let payload_hash;
                let mut req_builder = RequestBuilder::new("POST", "127.0.0.1", 9999, "/resource");

                // add a body hash, if we require such a thing
                if self.require_hash {
                    payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_ref());
                    req_builder = req_builder.hash(&payload_hash[..]);
                }

                let request = req_builder.request();

                // temp
                let header = self.header.clone().expect("expected header");

                assert_eq!(header.id, Some("test-client".to_string()));
                assert_eq!(header.ext, None);
                let key = Key::new(vec![1u8; 32], &SHA256);
                if !request.validate_header(&header, &key, Duration::from_secs(60)) {
                    panic!("header validation failed");
                }

                let body = b"OK";
                let payload_hash;
                let mut resp_builder = request.make_response_builder(&header).ext("server-ext");
                if self.send_hash {
                    payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body);
                    resp_builder = resp_builder.hash(&payload_hash[..]);
                }
                let server_hdr = resp_builder.response().make_header(&key).unwrap();

                Ok(Async::Ready(
                    Response::new()
                        .with_header(ContentLength(body.len() as u64))
                        .with_header(ServerAuthorization(HawkScheme(server_hdr)))
                        .with_body(body.as_ref()),
                ))
            }

            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => Err(err),
        }
    }
}

struct HeaderService {
    require_hash: bool,
    send_hash: bool,
}

impl Service for HeaderService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    type Future = ServerHeaderValidatorFuture;

    fn call(&self, req: Request) -> Self::Future {
        // get the Authorization header the client sent, if any
        let header = req
            .headers()
            .get::<Authorization<HawkScheme>>()
            .map(|h| h.clone());

        ServerHeaderValidatorFuture {
            header: header,
            require_hash: self.require_hash,
            send_hash: self.send_hash,
            body_stream: req.body().concat2(),
        }
    }
}

fn run_client_server(
    client_send_hash: bool,
    server_require_hash: bool,
    server_send_hash: bool,
    client_require_hash: bool,
) {
    // Hyper, really Tokio, bizarrely creates a new Service for each connection
    let service_factory = move || {
        Ok(HeaderService {
            require_hash: server_require_hash,
            send_hash: server_send_hash,
        })
    };
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = Http::new().bind(&addr, service_factory).unwrap();
    let local_address = server.local_addr().unwrap();

    // call the server using a Hyper client; this must all be in the same function
    // body to avoid lots of async lifetime issues
    let credentials = Credentials {
        id: "test-client".to_string(),
        key: Key::new(vec![1u8; 32], &SHA256),
    };
    let body = "foo=bar";
    let url = Url::parse("http://127.0.0.1:9999/resource").unwrap();

    // build a hawk::Request for this request
    let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_bytes());
    let mut req_builder = RequestBuilder::from_url("POST", &url).unwrap();
    if client_send_hash {
        req_builder = req_builder.hash(&payload_hash[..]);
    }
    let hawk_req = req_builder.request();

    let url = format!("http://127.0.0.1:{}", local_address.port())
        .parse()
        .unwrap();

    // build a hyper::Request for this request (using the real port)
    let mut req = Request::new(Method::Post, url);
    let req_header = hawk_req.make_header(&credentials).unwrap();
    req.headers_mut()
        .set(Authorization(HawkScheme(req_header.clone())));
    req.set_body(body);

    // use the server's tokio Core, since each server creates its own (?!)
    // https://github.com/hyperium/hyper/issues/1075
    let handle = server.handle();
    let client = Client::new(&handle);
    let client_fut = client
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
            assert_eq!(body.as_ref(), b"OK");

            // most fields in `Server-Authorization: Hawk` are omitted
            assert_eq!(server_hdr.id, None);
            assert_eq!(server_hdr.ts, None);
            assert_eq!(server_hdr.nonce, None);
            assert_eq!(server_hdr.ext, Some("server-ext".to_string()));
            assert_eq!(server_hdr.app, None);
            assert_eq!(server_hdr.dlg, None);

            let resp_payload_hash;
            let mut resp_builder = hawk_req.make_response_builder(&req_header);
            if client_require_hash {
                resp_payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_ref());
                resp_builder = resp_builder.hash(&resp_payload_hash[..]);
            }

            let response = resp_builder.response();
            if !response.validate_header(&server_hdr, &credentials.key) {
                panic!("authentication of response header failed");
            }
        })
        .map_err(|e| {
            panic!("{:?}", e);
        });
    server.run_until(client_fut).unwrap();

    drop(client);
    drop(handle);
}

#[test]
fn no_hashes() {
    run_client_server(false, false, false, false);
}

#[test]
fn client_sends() {
    run_client_server(true, false, false, false);
}

#[test]
fn server_requires() {
    run_client_server(true, true, false, false);
}

#[test]
fn server_sends() {
    run_client_server(true, true, true, false);
}

#[test]
fn client_requires() {
    run_client_server(true, true, true, true);
}

#[test]
fn response_hash_only() {
    run_client_server(false, false, true, true);
}

struct ServerBewitValidatorFuture {
    req: Request,
}

impl Future for ServerBewitValidatorFuture {
    type Item = Response;
    type Error = hyper::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // begin by extracting the bewit from the path
        let mut path = Cow::Owned(self.req.uri().to_string());
        println!("got req path {}", path);
        let bewit = Bewit::from_path(&mut path)
            .expect("error parsing bewit")
            .expect("no bewit found");
        println!("parsed path {}", path);

        // then proceeed to validate with that modified path
        let request = RequestBuilder::new("GET", "127.0.0.1", 9999, path.as_ref()).request();

        assert_eq!(bewit.ext(), None);
        let key = Key::new(vec![1u8; 32], &SHA256);
        if !request.validate_bewit(&bewit, &key) {
            panic!("bewit validation failed");
        }

        let body = b"OK";
        Ok(Async::Ready(
            Response::new()
                .with_header(ContentLength(body.len() as u64))
                .with_body(body.as_ref()),
        ))
    }
}

struct BewitService {}

impl Service for BewitService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    type Future = ServerBewitValidatorFuture;

    fn call(&self, req: Request) -> Self::Future {
        ServerBewitValidatorFuture { req }
    }
}

#[test]
fn bewit() {
    // Hyper, really Tokio, bizarrely creates a new Service for each connection
    let service_factory = move || Ok(BewitService {});
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = Http::new().bind(&addr, service_factory).unwrap();
    let local_address = server.local_addr().unwrap();

    // call the server using a Hyper client; this must all be in the same function
    // body to avoid lots of async lifetime issues
    let credentials = Credentials {
        id: "test-client".to_string(),
        key: Key::new(vec![1u8; 32], &SHA256),
    };
    let url = Url::parse("http://127.0.0.1:9999/resource?foo=bar").unwrap();

    // build a hawk::Request for this request
    let req_builder = RequestBuilder::from_url("GET", &url).unwrap();
    println!("req_builder: {:?}", req_builder);
    let hawk_req = req_builder.request();

    let url = format!(
        "http://127.0.0.1:{}/resource?bewit={}&foo=bar",
        local_address.port(),
        hawk_req
            .make_bewit_with_ttl(&credentials, Duration::from_secs(60))
            .unwrap()
            .to_str()
    );
    let url = url.parse().unwrap();

    // build a hyper::Request for this request (using the real port)
    let req = Request::new(Method::Get, url);
    println!("{:?}", req);

    // use the server's tokio Core, since each server creates its own (?!)
    // https://github.com/hyperium/hyper/issues/1075
    let handle = server.handle();
    let client = Client::new(&handle);
    let client_fut = client
        .request(req)
        .and_then(|res| {
            println!("{:?}", res);
            assert_eq!(res.status(), hyper::Ok);
            res.body().concat2()
        })
        .map(|body| {
            println!("res body {:?}", body);

            assert_eq!(body.as_ref(), b"OK");
        })
        .map_err(|e| {
            panic!("{:?}", e);
        });
    server.run_until(client_fut).unwrap();

    drop(client);
    drop(handle);
}
