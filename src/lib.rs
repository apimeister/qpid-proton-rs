use c_binding::*;
use std::ffi::CString;
use std::ffi::CStr;
use uuid::Uuid;
use std::collections::HashMap;

use log::{info, debug,error};
pub mod c_binding;

/// Sasl Basic Auth information
pub struct SaslAuth {
  pub username: String,
  pub password: String
}

#[allow(dead_code)]
pub struct Connection {
  connection: *mut c_binding::pn_connection_t,
  transport: *mut c_binding::pn_transport_t,
  link: *mut c_binding::pn_link_t,
  proactor: *mut c_binding::pn_proactor_t,
}

/// represents a Message
#[allow(dead_code)]
#[derive(Debug,Clone)]
pub struct Message{
  pub body: String,
  pub header: Option<HashMap<String,String>>
}

impl Connection {
  pub fn send_message(&self, payload: String){
    unsafe{
      //check link credit
      if pn_link_credit(self.link) > 0 {
        let counter_string = CString::new(Uuid::new_v4().to_string()).unwrap();
        let dtag = pn_dtag(counter_string.as_ptr(), 1);
        pn_delivery(self.link, dtag);
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
        info!("pn_message_encode: {}",result);
        info!("buffer size {}",buf_size);
        let result = pn_link_send(self.link, buf_ref, buf_size);
        info!("pn_link_send: {}",result);
        let result = pn_link_advance(self.link);
        info!("pn_link_advance: {}",result);
        pn_message_clear(message);
        self.wait_for(pn_event_type_t::PN_DELIVERY);
      }
    }
  }
  
  fn wait_for(&self, target: pn_event_type_t){
    unsafe{
      loop {
        let events = pn_proactor_wait(self.proactor);
        let mut should_continue = true;
        loop {
          let event = pn_event_batch_next(events);
          if event.is_null() {
            break
          }
          //handle single event
          match pn_event_type(event) {
            // target => {
            //   println!("matched target {:?}",pn_event_type(event));
            //   should_continue = false;
            //   break;
            // },
            _ => {
              if pn_event_type(event) == target {
                info!("matched target {:?}",pn_event_type(event));
                should_continue = false;
                break;  
              }else{
                debug!("{:?}",pn_event_type(event));
              }
            }
          }
        }
        pn_proactor_done(self.proactor, events);
        if !should_continue {
          break;
        }
      }
    }
  }
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

    let log_level = log::max_level();
    if log_level == log::LevelFilter::Trace {
      //enable logging
      let logger = pn_transport_logger(transport);
      pn_logger_set_mask(logger, pn_log_subsystem_t::PN_SUBSYSTEM_ALL, pn_log_level_t::PN_LEVEL_ALL);
    }
    match auth {
      Some(auth) => {
        pn_transport_require_auth(transport,true);
        pn_transport_require_encryption(transport,true);
        pn_connection_set_user(connection, CString::new(auth.username.clone()).unwrap().as_ptr());
        pn_connection_set_password(connection, CString::new(auth.password.clone()).unwrap().as_ptr());
        pn_connection_set_hostname(connection, CString::new(host.clone()).unwrap().as_ptr());
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
            info!("PN_CONNECTION_INIT: connection init");
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
              proactor: proactor,
            });
            should_continue = true;
          },
          pn_event_type_t::PN_TRANSPORT_ERROR =>{
            error!("PN_TRANSPORT_ERROR: something went wrong");
            let condition = pn_transport_condition(transport);
            let name = pn_condition_get_name(condition);
            let name2 = CStr::from_ptr(name).to_str().unwrap();
            let description = pn_condition_get_description(condition);
            let description2 = CStr::from_ptr(description).to_str().unwrap();
            error!("name: {}",name2);
            error!("desc: {}",description2);
          },
          pn_event_type_t::PN_LINK_FLOW => {
            info!("PN_LINK_FLOW: link ready");
            should_continue = false;
          },
          _ => {
            info!("{:?}",pn_event_type(event));
          }
        }
      }
      info!("pn_proactor_done");
      pn_proactor_done(proactor, events);
      if !should_continue {
        break;
      }
    }
  }
  result
}

