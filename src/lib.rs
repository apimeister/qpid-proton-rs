use c_binding::*;
use std::os::raw::c_char;
use std::ffi::CString;
use std::ffi::CStr;

pub mod c_binding;

pub struct SaslAuth {
  pub username: String,
  pub password: String
}

pub struct Connection {
  connection: *mut c_binding::pn_connection_t,
  transport: *mut c_binding::pn_transport_t,
  link: *mut c_binding::pn_link_t,
}

pub fn connect(host: String, port: u16, auth: Option<SaslAuth>, destination: String) -> Option<Connection> {
  let mut result: Option<Connection> = None;
  unsafe{
    let proactor = pn_proactor();
    let addr = format!("{}:{}",host,port);
    let host2 = host.clone();
    let dest2 = destination.clone();
    let c_addr = CString::new(addr).unwrap();
    let transport = pn_transport();
    let connection = pn_connection();
    //enable logging
    // let logger = pn_transport_logger(transport);
    // pn_logger_set_mask(logger, pn_log_subsystem_t::PN_SUBSYSTEM_ALL, pn_log_level_t::PN_LEVEL_ALL);

    match auth {
      Some(auth) => {
        pn_transport_require_auth(transport,true);
        pn_transport_require_encryption(transport,true);
        pn_connection_set_user(connection, CString::new(auth.username).unwrap().as_ptr());
        pn_connection_set_password(connection, CString::new(auth.password).unwrap().as_ptr());
        pn_connection_set_hostname(connection, CString::new(host).unwrap().as_ptr());
        let sasl = pn_sasl(transport);
        pn_sasl_set_allow_insecure_mechs(sasl, true);
        pn_sasl_allowed_mechs(sasl, CString::new("PLAIN").unwrap().as_ptr());
    
      },
      None => {}
    }   
    pn_proactor_connect2(proactor,connection, transport, c_addr.as_ptr());
    loop {
      let events = pn_proactor_wait(proactor);
      let mut should_continue = true;
      loop {
        let host3 = host2.to_string();
        let dest3 = dest2.to_string();
        let event = pn_event_batch_next(events);
        if event.is_null() {
          break
        }
        //handle single event
        match pn_event_type(event) {
          pn_event_type_t::PN_CONNECTION_INIT =>{
            println!("PN_CONNECTION_INIT: connection init");
            let c = pn_event_connection(event);
            let s = pn_session(pn_event_connection(event));
            let unqiue_id = "unique";
            let c_unique_id = CString::new(unqiue_id).unwrap();
            pn_connection_set_container(c, c_unique_id.as_ptr());
            let ssl = pn_ssl(transport);
            pn_ssl_init(ssl,std::ptr::null_mut(),std::ptr::null_mut());
            pn_ssl_set_peer_hostname(ssl,CString::new(host3).unwrap().as_ptr());
            pn_connection_open(c);
            pn_session_open(s);
            let sender_name = "sender";
            let c_sender_name = CString::new(sender_name).unwrap();
            let l = pn_sender(s, c_sender_name.as_ptr());
            let c_amqp_address = CString::new(dest3).unwrap();
            pn_terminus_set_address(pn_link_target(l), c_amqp_address.as_ptr());
            pn_link_open(l);
            result = Some(Connection{
              transport: transport,
              connection: connection,
              link: l,
            });
            should_continue = true;
          },
          pn_event_type_t::PN_LINK_FLOW => {
            should_continue = false;
          },
          _ => {
            println!("{:?}",pn_event_type(event));
          }
        }
      }
      if !should_continue {
        break;
      }
      pn_proactor_done(proactor, events);
    }
    
  }
  result
}

pub fn send_message(connection: Connection, payload: String){
  unsafe{
    //check link credit
    if pn_link_credit(connection.link) > 0 {
      let counter_string = CString::new(payload.clone()).unwrap();
      let dtag = pn_dtag(counter_string.as_ptr(), 1);
      pn_delivery(connection.link, dtag);
      let message = pn_message();
      let body = pn_message_body(message);
      pn_data_enter(body);
      let content = CString::new(payload.clone()).unwrap();
      pn_data_put_string(body, pn_bytes(payload.len(), content.as_ptr()));
      pn_data_exit(body);
      let mut buf_size: usize = 1024*1024;
      let buf_vec:Vec<i8> = vec![0; buf_size];
      let buf_ref: *const std::os::raw::c_char = buf_vec.as_ptr();
      let result = pn_message_encode(message,buf_ref,&mut buf_size);
      println!("pn_message_encode: {}",result);
      println!("buffer size {}",buf_size);
      let result = pn_link_send(connection.link, buf_ref, buf_size);
      println!("pn_link_send: {}",result);
      let result = pn_link_advance(connection.link);
      println!("pn_link_advance: {}",result);
      pn_message_clear(message);
    }
  }
}