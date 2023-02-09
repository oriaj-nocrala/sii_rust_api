pub mod dte;
pub mod requests;

extern crate reqwest;
extern crate xml;

use actix_web::{HttpServer, get, HttpResponse, Responder, middleware::DefaultHeaders, http::header, web};
use dte::dte::{SignatureValue, UriAttributes};
use reqwest::{Response};
use xml::writer::{EventWriter, XmlEvent};
use openssl::{pkcs12::Pkcs12, hash::MessageDigest, sign::Signer, base64, pkey::{PKey, Private}, x509::X509, sha::Sha1};

use crate::{dte::dte::{
    Signature, 
    X509Data, 
    KeyInfo, 
    SignedInfo, 
    CanonicalizationMethod, 
    SignatureMethod, 
    Reference, 
    Transforms, 
    Transform, 
    DigestMethod, 
    AlgorithmAttributes, 
    DigestValue, 
    KeyValue,
    RSAKeyValue,
    Modulus, 
    Exponent, 
    X509Certificate
    }, requests::get_token_rq::{GetTokenRequest, Item}};

use std::env;

#[derive(Clone)]
struct PfxData{
    path: std::path::PathBuf,
    password: String
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let ip_addr = "localhost";
    let port = "6969";

    let args = env::args().collect::<Vec<String>>();
    if args.len() < 5 {
        println!("Uso: {} -f <cert.pfx> -p <pfx pass>", args[0]);
        return Ok(());
    }

    let mut pfx_data = PfxData {
        path: std::path::PathBuf::from(""),
        password: "".to_string()
    };
    
    for i in 1..args.len() {
        if args[i] == "-f" {
            let file = args[i + 1].clone();
            let path = std::path::Path::new(&file);
            if !file.ends_with(".pfx") {
                println!("Error: El archivo debe tener extension .pfx");
                return Ok(());
            }
            if !path.exists() {
                println!("Error: El archivo no existe");
                return Ok(());
            }
            pfx_data.path = path.to_path_buf();
        } else if args[i] == "-p" {
            pfx_data.password = args[i + 1].clone();
        }
    }

    let data = web::Data::new(pfx_data.clone());

    match HttpServer::new(move || {
        actix_web::App::new()
        .wrap(DefaultHeaders::new().add((header::CONTENT_TYPE, "text/xml")))
            .app_data(data.clone())
            .service(get_seed_handler)
            .service(show_seed_request_handler)
            .service(show_seed_response_handler)
            .service(show_sign_request_handler)
            .service(sign_seed_handler)
    })
    .bind(format!("{}:{}", ip_addr, port))
    {
        Ok(server) => {
            println!("Server running at http://{}:{}", ip_addr, port);
            println!("Endpoints: /cr-seed-full-response, /seed-request, /seed-response, /sign-request, /sign-seed");
            server
        },
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Error: {}", e)))
    }
    .run()
    .await
}




#[derive(serde::Serialize)]
struct Semilla {
    semilla: u32
}

#[get("/cr-seed-full-response")]
async fn get_seed_handler() -> impl Responder {
    let response = match send_post_soap().await {
        Ok(res) => res,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e))
    };

    return HttpResponse::Ok().body(response.text().await.unwrap());

}

fn response_from_post_soap() -> String {
    let mut xml_writer = EventWriter::new(Vec::new());

    xml_writer.write(XmlEvent::start_element("SOAP-ENV:Envelope")
        .default_ns("http://schemas.xmlsoap.org/soap/envelope/")
        .ns("SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
        .ns("SOAP-ENC", "http://schemas.xmlsoap.org/soap/encoding/")
        .ns("xsi", "http://www.w3.org/2001/XMLSchema-instance")
        .ns("xsd", "http://www.w3.org/2001/XMLSchema")
        .attr("SOAP-ENC:encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/"))
        .unwrap();
    xml_writer.write(XmlEvent::start_element("SOAP-ENV:Body")
        .default_ns("http://schemas.xmlsoap.org/soap/envelope/")
        .ns("m", "https://maullin.sii.cl/DTEWS/CrSeed.jws"))
        .unwrap();
    xml_writer.write(XmlEvent::start_element("m:getSeed")
        .ns("m", "https://maullin.sii.cl/DTEWS/CrSeed.jws")).unwrap();
    xml_writer.write(XmlEvent::end_element()).unwrap();
    xml_writer.write(XmlEvent::end_element()).unwrap();
    xml_writer.write(XmlEvent::end_element()).unwrap();

    String::from_utf8(xml_writer.into_inner()).unwrap()
}

async fn send_post_soap() -> Result<Response, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client.post("https://maullin.sii.cl/DTEWS/CrSeed.jws")
        .header("Content-Type", "text/xml")
        .header("SOAPAction", "https://maullin.sii.cl/DTEWS/CrSeed.jws/getSeed")
        .body(response_from_post_soap())
        .send()
        .await?;

    Ok(response)
}


#[get("/seed-request")]
async fn show_seed_request_handler() -> impl Responder {
    let response = response_from_post_soap();


    return HttpResponse::Ok().body(response);
}

#[get("/seed-response")]
async fn show_seed_response_handler() -> impl Responder {
    let response = match send_post_soap().await {
        Ok(res) => res,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e))
    };

    let response_text = response.text().await.unwrap();
    let pos = response_text.clone().find("<ns1:getSeedReturn xsi:type=\"xsd:string\">").unwrap();
    let pos2 = response_text.clone().find("</ns1:getSeedReturn>").unwrap();

    let seed_response = response_text.as_str()[pos+41..pos2].to_string();
    let seed_response = seed_response.replace("&lt;", "<");
    let seed_response = seed_response.replace("&gt;", ">");



    return HttpResponse::Ok().body(seed_response);
}

#[get("/sign-request")]
async fn show_sign_request_handler() -> impl Responder {
    let response = send_post_soap().await.unwrap().text().await.unwrap();
    let response = response.replace("&lt;", "<");
    let response = response.replace("&gt;", ">");
    let pos = response.find("<SEMILLA>").unwrap();
    let pos2 = response.find("</SEMILLA>").unwrap();
    let semilla = response.as_str()[pos+9..pos2].to_string();
    println!("{}",semilla);
    return HttpResponse::Ok().body(semilla);
}

#[get("/sign-seed")]
async fn sign_seed_handler(pfx_data: web::Data<PfxData>) -> impl Responder {

    // let response = send_post_soap().await.unwrap().text().await.unwrap();
    // let response = response.replace("&lt;", "<");
    // let response = response.replace("&gt;", ">");
    // let pos = response.find("<SEMILLA>").unwrap();
    // let pos2 = response.find("</SEMILLA>").unwrap();
    // let semilla = response.as_str()[pos+9..pos2].to_string();

    let semilla = "093640954482".to_string();
    let mut hasher = Sha1::new();
    hasher.update(semilla.clone().as_bytes());
    let semilla_sha1 = hasher.finish();

    // abrir archivo pfx desde pfx_data.path

    let pfx = std::fs::read(pfx_data.path.clone()).unwrap();

    let signed_seed = sign_seed(pfx.clone(), semilla.clone(), pfx_data.password.clone()).await.unwrap();
    let signed_seed = get_signature_value(signed_seed);
    let x509_data = get_cert(pfx.to_vec(), pfx_data.password.clone()).unwrap();

    let signature = Signature{
        signed_info: SignedInfo{
            canonicalization_method: CanonicalizationMethod{
                algorithm: AlgorithmAttributes{algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string()}
            },
            signature_method: SignatureMethod{
                algorithm: AlgorithmAttributes{algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_string()}
            },
            reference: Reference{
                uri: UriAttributes{uri: "".to_string()},
                transforms: Transforms{
                    transforms: vec![
                        Transform{
                            algorithm: AlgorithmAttributes{algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string()}
                        },
                        Transform{
                            algorithm: AlgorithmAttributes{algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string()}
                        }
                    ]
                },
                digest_method: DigestMethod{
                    algorithm: AlgorithmAttributes{algorithm: "http://www.w3.org/2000/09/xmldsig#sha1".to_string()}
                },
                digest_value: DigestValue{value: base64::encode_block(&semilla_sha1)}

            }
        },
        signature_value: signed_seed,
        key_info: KeyInfo{
            key_value: KeyValue{
                rsa_key_value: get_rsa_key_value(pfx.to_vec(), pfx_data.password.clone()).unwrap()
            },
            x509_data
        }
    };

    let token_request = GetTokenRequest {
        header: "header".to_string(),
        item: Item {
            seed: semilla,
        },
        signature
    };

    return HttpResponse::Ok().json(&token_request);
}



fn get_signature_value(signed_seed: Vec<u8>) -> SignatureValue {
    let signed_seed = base64::encode_block(&signed_seed);
    SignatureValue { value: signed_seed }
}

async fn sign_seed(pfx: Vec<u8>, semilla: String, pass: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pfx = Pkcs12::from_der(&pfx)?;
    // let cert = pfx.cert;
    // let key = pfx.pkey;

    let parsed_pkcs12 = pfx.parse(pass.as_str())?;
    let pkey = parsed_pkcs12.pkey;
    // firmar la semilla
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(semilla.as_bytes())?;
    let semilla_firmada = signer.sign_to_vec()?;
    Ok(semilla_firmada)
}

fn get_rsa_key_value(pfx: Vec<u8>, pass: String) -> Result<RSAKeyValue, Box<dyn std::error::Error>> {
    let pfx = Pkcs12::from_der(&pfx)?;
    let parsed_pkcs12 = pfx.parse(pass.as_str())?;
    let cert = parsed_pkcs12.cert;
    let cert = cert.to_pem()?;
    let cert = String::from_utf8(cert)?;
    let cert = cert.replace("-----BEGIN CERTIFICATE-----", "");
    let cert = cert.replace("-----END CERTIFICATE-----", "");
    let cert = cert.replace("\r", "");
    let cert = cert.replace("\n", "");
    let cert = base64::decode_block(&cert)?;
    let cert = X509::from_der(&cert)?;
    //separar en funcion viejo
    let rsa = cert.public_key()?.rsa()?;
    let modulus = rsa.n().to_vec();
    let exponent = rsa.e().to_vec();
    let modulus = base64::encode_block(&modulus);
    let exponent = base64::encode_block(&exponent);
    Ok(RSAKeyValue {
        modulus: Modulus { value: modulus },
        exponent: Exponent { value: exponent },
    })
}

fn get_pkey(pfx: Vec<u8>, pass: String) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let pfx = Pkcs12::from_der(&pfx)?;
    let parsed_pkcs12 = pfx.parse(pass.as_str())?;
    let key = parsed_pkcs12.pkey;
    Ok(key)
}
fn get_cert(pfx: Vec<u8>, pass: String) -> Result<X509Data, Box<dyn std::error::Error>> {
    let pfx = Pkcs12::from_der(&pfx)?;
    let parsed_pkcs12 = pfx.parse(pass.as_str())?;
    let cert = parsed_pkcs12.cert;
    let cert = cert.to_pem()?;
    let cert = String::from_utf8(cert)?;
    let cert = cert.replace("-----BEGIN CERTIFICATE-----", "");
    let cert = cert.replace("-----END CERTIFICATE-----", "");
    let cert = cert.replace("\n", "");
    let cert = cert.replace("\r", "");
    let cert = cert.replace(" ", "");
    let cert = cert.replace("\t", "");
    let cert = cert.replace("\u{0}", "");

    let x509_certificate = X509Certificate{value: cert};

    let cert = X509Data{ x509_certificate: x509_certificate };

    Ok(cert)
    
}