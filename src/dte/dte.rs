
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct Attributes{
 
    #[serde(rename = "xmlns")]
    pub xmlns: String,
    
    #[serde(rename = "xmlns:xsi")]
    pub xmlns_xsi: String,
    
    #[serde(rename = "xsi:schemaLocation")]
    pub xsi_schema_location: String,
    
    #[serde(rename = "version")]
    pub version: String,
    
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnvioDTE
{
    #[serde(flatten)]
    pub attributes: Attributes,

    #[serde(rename = "SetDTE")]
    pub set_dte: SetDTE,

    #[serde(rename = "Signature")]
    pub signature: Signature
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnvioDTEAttributes{
    
    #[serde(rename = "xmlns")]
    pub xmlns: String,
    
    #[serde(rename = "xmlns:xsi")]
    pub xmlns_xsi: String,
    
    #[serde(rename = "xsi:schemaLocation")]
    pub xsi_schema_location: String,
    
    #[serde(rename = "version")]
    pub version: String,
    
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IDAttributes{
    #[serde(rename = "ID")]
    pub id: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetDTE{

    #[serde(flatten)]
    pub id_attributes: IDAttributes,

    #[serde(rename = "Caratula")]
    pub caratula: Caratula,

    #[serde(rename = "DTE")]
    pub dte: DTE
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DTE{
    #[serde(rename = "Documento")]
    pub documento: Documento,

    #[serde(rename = "Signature")]
    pub signature: Signature
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Documento{

    #[serde(rename = "Encabezado")]
    pub encabezado: Encabezado,

    #[serde(rename = "Detalle")]
    pub detalle: Detalle,

    #[serde(rename = "TED")]
    pub ted: TED,

    #[serde(rename = "TmstFirma")]
    pub tmst_firma: String,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct Detalle{
    
        #[serde(rename = "NroLinDet")]
        pub numero_linea_detalle: String,

        #[serde(rename = "CdgItem")]
        pub codigo_item: CdgItem,
    
        #[serde(rename = "NmbItem")]
        pub nombre_item: String,

        #[serde(rename = "DscItem")]
        pub descripcion_item: String,
    
        #[serde(rename = "QtyItem")]
        pub cantidad_item: String,
    
        #[serde(rename = "PrcItem")]
        pub precio_item: String,
    
        #[serde(rename = "MontoItem")]
        pub monto_item: String,
    
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CdgItem{
    
    #[serde(rename = "TpoCodigo")]
    pub tipo_codigo: String,

    #[serde(rename = "VlrCodigo")]
    pub valor_codigo: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Encabezado{

    #[serde(rename = "IdDoc")]
    pub id_doc: IdDoc,

    #[serde(rename = "Emisor")]
    pub emisor: Emisor,

    #[serde(rename = "Receptor")]
    pub receptor: Receptor,

    #[serde(rename = "Totales")]
    pub totales: Totales,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct IdDoc{

    #[serde(rename = "TipoDTE")]
    pub tipo_dte: String,

    #[serde(rename = "Folio")]
    pub folio: String,

    #[serde(rename = "FchEmis")]
    pub fch_emis: String,

    #[serde(rename = "FmaPago")]
    pub fma_pago: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Emisor{

    #[serde(rename = "RUTEmisor")]
    pub rut_emisor: String,

    #[serde(rename = "RznSoc")]
    pub razon_social: String,

    #[serde(rename = "GiroEmis")]
    pub giro_emisor: String,

    #[serde(rename = "Acteco")]
    pub acteco: String,

    #[serde(rename = "DirOrigen")]
    pub direccion_origen: String,

    #[serde(rename = "CmnaOrigen")]
    pub comuna_origen: String,

    #[serde(rename = "CiudadOrigen")]
    pub ciudad_origen: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Receptor{

    #[serde(rename = "RUTRecep")]
    pub rut_receptor: String,

    #[serde(rename = "RznSocRecep")]
    pub razon_social_receptor: String,

    #[serde(rename = "GiroRecep")]
    pub giro_receptor: String,

    #[serde(rename = "DirRecep")]
    pub direccion_receptor: String,

    #[serde(rename = "CmnaRecep")]
    pub comuna_receptor: String,

    #[serde(rename = "CiudadRecep")]
    pub ciudad_receptor: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Totales{

    #[serde(rename = "MntNeto")]
    pub monto_neto: String,

    #[serde(rename = "IVA")]
    pub iva: String,

    #[serde(rename = "MntTotal")]
    pub monto_total: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TED{

    #[serde(flatten)]
    pub version: Version,

    #[serde(rename = "DD")]
    pub dd: DD,

    #[serde(rename = "FRMT")]
    pub frmt: FRMT
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Version{
    #[serde(rename = "version")]
    pub version: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DD{
    #[serde(rename = "RE")]
    pub rut_emisor: String,

    #[serde(rename = "TD")]
    pub tipo_dte: String,

    #[serde(rename = "F")]
    pub folio: String,

    #[serde(rename = "FE")]
    pub fecha_emision: String,

    #[serde(rename = "RR")]
    pub rut_receptor: String,

    #[serde(rename = "RSR")]
    pub razon_social_receptor: String,

    #[serde(rename = "MNT")]
    pub monto_total: String,

    #[serde(rename = "IT1")]
    pub item1: String,

    #[serde(rename = "CAF")]
    pub caf: CAF,

    #[serde(rename = "TSTED")]
    pub tst_edicion: String
}


#[derive(Serialize, Deserialize, Debug)]
pub struct CAF{
    #[serde(rename = "DA")]
    pub documento_autorizado: DA,

    #[serde(rename = "FRMA")]
    pub frma: FRMA
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DA{
    #[serde(rename = "RE")]
    pub rut_emisor: String,

    #[serde(rename = "RS")]
    pub razon_social: String,

    #[serde(rename = "TD")]
    pub tipo_dte: String,

    #[serde(rename = "RNG")]
    pub rng: Rng,

    #[serde(rename = "FA")]
    pub fecha_autorizacion: String,

    #[serde(rename = "RSAPK")]
    pub rsapk: Rsapk,

    #[serde(rename = "IDK")]
    pub idk: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rng{
    #[serde(rename = "D")]
    pub d: String,

    #[serde(rename = "H")]
    pub h: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rsapk{
    #[serde(rename = "M")]
    pub m: String,

    #[serde(rename = "E")]
    pub e: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FRMA{
    #[serde(flatten)]
    pub attributes: Algoritmo,

    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Algoritmo{
    #[serde(rename = "algoritmo")]
    pub algoritmo: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FRMT{

    #[serde(flatten)]
    pub attributes: Algoritmo,

    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Caratula{
    #[serde(rename = "RutEmisor")]
    pub rut_emisor: String,

    #[serde(rename = "RutEnvia")]
    pub rut_envia: String,

    #[serde(rename = "RutReceptor")]
    pub rut_receptor: String,

    #[serde(rename = "FchResol")]
    pub fch_resol: String,

    #[serde(rename = "NroResol")]
    pub nro_resol: String,

    #[serde(rename = "TmstFirmaEnv")]
    pub tmst_firma_env: String,

    #[serde(rename = "SubTotDTE")]
    pub sub_tot_dte: Vec<SubTotDTE>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubTotDTE{
    #[serde(rename = "TpoDTE")]
    pub tpo_dte: String,

    #[serde(rename = "NroDTE")]
    pub nro_dte: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Signature{
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,

    #[serde(rename = "SignatureValue")]
    pub signature_value: SignatureValue,

    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedInfo{
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,

    #[serde(rename = "SignatureMethod")]
    pub signature_method: SignatureMethod,

    #[serde(rename = "Reference")]
    pub reference: Reference
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CanonicalizationMethod{
    #[serde(flatten)]
    pub algorithm: AlgorithmAttributes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AlgorithmAttributes{
    #[serde(rename = "Algorithm")]
    pub algorithm: String
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureMethod{
    #[serde(flatten)]
    pub algorithm: AlgorithmAttributes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Reference{
    #[serde(flatten)]
    pub uri: UriAttributes,

    #[serde(rename = "Transforms")]
    pub transforms: Transforms,

    #[serde(rename = "DigestMethod")]
    pub digest_method: DigestMethod,

    #[serde(rename = "DigestValue")]
    pub digest_value: DigestValue
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UriAttributes{
    #[serde(rename = "URI")]
    pub uri: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Transforms{
    #[serde(rename = "Transform")]
    pub transforms: Vec<Transform>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Transform{
    #[serde(flatten)]
    pub algorithm: AlgorithmAttributes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DigestMethod{
    #[serde(flatten)]
    pub algorithm: AlgorithmAttributes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DigestValue{
    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureValue{
    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyInfo{

    #[serde(rename = "KeyValue")]
    pub key_value: KeyValue,

    #[serde(rename = "X509Data")]
    pub x509_data: X509Data,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyValue{
    #[serde(rename = "RSAKeyValue")]
    pub rsa_key_value: RSAKeyValue
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RSAKeyValue{
    #[serde(rename = "Modulus")]
    pub modulus: Modulus,

    #[serde(rename = "Exponent")]
    pub exponent: Exponent
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Modulus{
    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Exponent{
    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct X509Data{
    #[serde(rename = "X509Certificate")]
    pub x509_certificate: X509Certificate
}

#[derive(Serialize, Deserialize, Debug)]
pub struct X509Certificate{
    #[serde(rename = "$value")]
    pub value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedKey{
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: EncryptionMethod,

    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,

    #[serde(rename = "CipherData")]
    pub cipher_data: CipherData,

    #[serde(rename = "EncryptionProperties")]
    pub encryption_properties: EncryptionProperties
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionMethod{
    #[serde(rename = "Algorithm")]
    pub algorithm: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherData{
    #[serde(rename = "CipherValue")]
    pub cipher_value: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionProperties{
    #[serde(rename = "EncryptionProperty")]
    pub encryption_property: EncryptionProperty
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionProperty{
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: EncryptionMethod,

    #[serde(rename = "CipherData")]
    pub cipher_data: CipherData
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData{
    #[serde(rename = "EncryptionMethod")]
    pub encryption_method: EncryptionMethod,

    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,

    #[serde(rename = "CipherData")]
    pub cipher_data: CipherData,

    #[serde(rename = "EncryptionProperties")]
    pub encryption_properties: EncryptionProperties
}

impl Default for EnvioDTE{
    fn default() -> Self {
        EnvioDTE{
            attributes: Attributes{
                xmlns: "http://www.sii.cl/SiiDte".to_string(),
                xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
                version: "1.0".to_string(),
                xsi_schema_location: "http://www.sii.cl/SiiDte EnvioDTE_v10.xsd".to_string()
            },
            set_dte: SetDTE{
                id_attributes: IDAttributes { id: "SetDoc".to_string() },
                caratula: Caratula{
                    rut_emisor: "76192083-9".to_string(),
                    rut_envia: "76192083-9".to_string(),
                    rut_receptor: "60803000-K".to_string(),
                    fch_resol: "2016-12-23T00:00:00".to_string(),
                    nro_resol: "0".to_string(),
                    tmst_firma_env: "2017-01-01T00:00:00".to_string(),
                    sub_tot_dte: vec![SubTotDTE{
                        tpo_dte: "33".to_string(),
                        nro_dte: "1".to_string()
                    }]
                },
                dte: DTE{
                    documento: Documento{
                        encabezado: Encabezado{
                            id_doc: IdDoc{
                                tipo_dte: "33".to_string(),
                                folio: "1".to_string(),
                                fch_emis: "2017-01-01".to_string(),
                                fma_pago: "1".to_string(),
                            },
                            emisor: Emisor{
                                rut_emisor: "76192083-9".to_string(),
                                razon_social: "EMPRESA DE PRUEBA".to_string(),
                                giro_emisor: "GIRO DE PRUEBA".to_string(),
                                acteco: "1234".to_string(),
                                direccion_origen: "CALLE 123".to_string(),
                                comuna_origen: "COMUNA 123".to_string(),
                                ciudad_origen: "CIUDAD 123".to_string(),
                            },
                            receptor: Receptor{
                                rut_receptor: "60803000-K".to_string(),
                                razon_social_receptor: "CLIENTE DE PRUEBA".to_string(),
                                giro_receptor: "GIRO DE PRUEBA".to_string(),
                                direccion_receptor: "CALLE 123".to_string(),
                                comuna_receptor: "COMUNA 123".to_string(),
                                ciudad_receptor: "CIUDAD 123".to_string(),
                            },
                            totales: Totales{
                                monto_neto: "100".to_string(),
                                iva: "19".to_string(),
                                monto_total: "119".to_string(),
                            }
                        },
                        detalle: Detalle{
                            numero_linea_detalle: "1".to_string(),
                            codigo_item: CdgItem{
                                tipo_codigo: "INT1".to_string(),
                                valor_codigo: "1".to_string(),
                            },
                            nombre_item: "ITEM DE PRUEBA".to_string(),
                            descripcion_item: "ITEM DE PRUEBA".to_string(),
                            cantidad_item: "1".to_string(),
                            precio_item: "100".to_string(),
                            monto_item: "100".to_string(),
                        },
                        ted: TED{
                            version: Version { version: "1.0".to_string() },
                            dd: DD{
                                rut_emisor: "76192083-9".to_string(),
                                tipo_dte: "33".to_string(),
                                folio: "1".to_string(),
                                fecha_emision: "2017-01-01".to_string(),
                                rut_receptor: "60803000-K".to_string(),
                                razon_social_receptor: "CLIENTE DE PRUEBA".to_string(),
                                monto_total: "119".to_string(),
                                item1: "ITEM DE PRUEBA".to_string(),
                                caf: CAF{
                                    documento_autorizado: DA{
                                        rut_emisor: "76192083-9".to_string(),
                                        razon_social: "EMPRESA DE PRUEBA".to_string(),
                                        tipo_dte: "33".to_string(),
                                        rng: Rng{
                                            d: "1".to_string(),
                                            h: "100".to_string(),
                                        },
                                        fecha_autorizacion: "2017-01-01".to_string(),
                                        rsapk: Rsapk{
                                            m: "m".to_string(),
                                            e: "e".to_string(),
                                        },
                                        idk: "idk".to_string(),
                                        }, // DA
                                    frma: FRMA{
                                        attributes: Algoritmo{
                                            algoritmo: "SHA1withRSA".to_string(),
                                        },
                                        value: "frma".to_string(),
                                    },
                                },
                                tst_edicion: "2017-01-01".to_string(),

                                },
                                frmt: FRMT { 
                                    attributes: Algoritmo { 
                                        algoritmo: "SHA1withRSA".to_string() 
                                    },
                                    value: "frmt".to_string(),
                                },
                            }, // Ted
                            tmst_firma: "2017-01-01T00:00:00".to_string(),
                        }, // Documento
                        signature: Signature{
                            signed_info: SignedInfo{
                                canonicalization_method: CanonicalizationMethod{
                                    algorithm: AlgorithmAttributes{ algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string() }},
                                signature_method: SignatureMethod{
                                     algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_string() }},
                                reference: Reference{
                                    uri: UriAttributes { uri: "#F996286T33".to_string() },
                                    transforms: Transforms { transforms: vec![
                                        Transform{
                                            algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string() }},
                                        ]},
                                    digest_method: DigestMethod{
                                        algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#sha1".to_string() },
                                    },
                                    digest_value: DigestValue { value: "digest_value".to_string() },
                                },
                            },
                            signature_value: SignatureValue{value: "signature_value".to_string()},
                            key_info: KeyInfo{
                                key_value: KeyValue{
                                    rsa_key_value: RSAKeyValue{
                                        modulus: Modulus{value: "modulus".to_string()},
                                        exponent: Exponent { value: "exponent".to_string() },
                                    },
                                },
                                x509_data: X509Data{
                                    x509_certificate: X509Certificate { value: "x509_certificate".to_string() },
                                },
                            },
                        }, // Signature
                    }, // DTE
                }, // SetDTE
                signature: Signature{
                    signed_info: SignedInfo{
                        canonicalization_method: CanonicalizationMethod{
                            algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string()},
                        },
                        signature_method: SignatureMethod{
                            algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_string()},
                        },
                        reference: Reference{
                            uri: UriAttributes { uri: "#F996286T33".to_string() },
                            transforms: Transforms{
                                transforms: vec![ Transform{
                                    algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string()},
                                }],
                            },
                            digest_method: DigestMethod{
                                algorithm: AlgorithmAttributes { algorithm: "http://www.w3.org/2000/09/xmldsig#sha1".to_string()},
                            },
                            digest_value: DigestValue { value: "digest_value".to_string() },
                        },
                    },
                    signature_value: SignatureValue { value: "signature_value".to_string() },
                    key_info: KeyInfo{
                        key_value: KeyValue{
                            rsa_key_value: RSAKeyValue{
                                modulus: Modulus{value: "modulus".to_string()},
                                exponent: Exponent{value: "exponent".to_string()},
                            },
                        },
                        x509_data: X509Data{
                            x509_certificate: X509Certificate { value: "x509_certificate".to_string()},
                        },
                    },
                }, // Signature
        } // EnvioDTE
    }
}

// impl EnvioDTE{
//     pub fn to_xml(){
//         let mut xml = String::new();
//         let mut writer = Writer::new_with_indent(&mut xml, b' ', 4);
//         let mut envio_dte = EnvioDTE::new();
//         envio_dte.to_xml(&mut writer);
//         println!("{}", xml);
//     }
// }