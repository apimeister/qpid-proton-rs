use qpid_proton_sys::*;
use std::ffi::CString;
use std::ffi::CStr;
use uuid::Uuid;
use std::collections::HashMap;

use log::{info, debug,error};

/// Sasl Basic Auth information
pub struct SaslAuth {
  pub username: String,
  pub password: String
}

#[allow(dead_code)]
pub struct Connection {
  connection: *mut pn_connection_t,
  transport: *mut pn_transport_t,
  proactor: *mut pn_proactor_t,
  session: *mut pn_session_t,
}

#[allow(dead_code)]
pub struct Link {
  link: *mut pn_link_t,
  proactor: *mut pn_proactor_t,
}

/// represents a Message
#[allow(dead_code)]
#[derive(Debug,Clone)]
pub struct Message{
  pub body: String,
  pub header: Option<HashMap<String,String>>
}

use std::os::raw::c_char;

#[allow(dead_code)]
extern "C" {
   pub fn pn_rwbytes(size: usize, start: *const c_char) -> pn_rwbytes_t;
   pub fn pn_message_set_content_encoding(msg: *mut pn_message_t,encoding: *const c_char);
   pub fn pn_message_data(msg: *mut pn_message_t,data: *mut pn_data_t) -> i32;
   pub fn pn_data_type(data: *mut pn_data_t) -> pn_type_t;
   pub fn pn_data_put_symbol	(	data: *mut pn_data_t,symbol: *mut pn_bytes_t) -> i32;
   pub fn pn_data_put_described	(data: *mut pn_data_t) -> i32;
}
impl Link {
  pub fn send_message(&self, payload: String){
    unsafe{
      //check link credit
      if pn_link_credit(self.link) > 0 {
        let counter_string = CString::new(Uuid::new_v4().to_string()).unwrap();
        let dtag = pn_dtag(counter_string.as_ptr(), 1);
        pn_delivery(self.link, dtag);
        let message = pn_message();
        let content_type = CString::new("application/json").unwrap();
        pn_message_set_content_type(message, content_type.as_ptr());
        let body = pn_message_body(message);
        pn_message_set_inferred(message, true);

        // pn_data_put_described(body);
        // pn_data_enter(body);
        // let descr = CString::new("string").unwrap();
        // let val = CString::new("val").unwrap();
        // pn_data_put_symbol(body, pn_bytes(6, descr.as_ptr()));
        // pn_data_put_string(body, pn_bytes(3, val.as_ptr()));
        // pn_data_exit(body);
        // let msg = CString::new("hello").unwrap();
        // let bytes = pn_bytes(5, msg.as_ptr());
        // pn_data_put_string(body, bytes);
        
        // pn_data_put_array(body, false, qpid_proton_sys::pn_type_t::PN_BYTE);
        // pn_data_enter(body);
        let content = CString::new(payload.clone()).unwrap();
        // println!("content: {:?}",content.clone().into_bytes());
        // pn_data_encode(body, content.as_ptr(), payload.len());
        pn_data_put_string(body, pn_bytes(payload.len(), content.as_ptr()));
        let t = pn_data_type(body);
        println!("data_type: {:?}",t);
        // pn_data_exit(body);
        let mut buf_size: usize = 100;
        let buf_vec:Vec<i8> = vec![0; buf_size];
        let buf_ref: *const std::os::raw::c_char = buf_vec.as_ptr();
        let result = pn_message_encode(message,buf_ref,&mut buf_size);
        info!("pn_message_encode: {}",result);
        info!("buffer size {}",buf_size);
        info!("buffer_raw: {:?}",buf_vec);
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
  /// wait for a message
  pub fn receive(&self) -> Message {
    let result = Message{
      body: "".to_string(),
      header: None,
    };
    unsafe{
      loop {
        let events = pn_proactor_wait(self.proactor);
        let mut should_continue = true;
        loop {
          info!("entering loop");
          let event = pn_event_batch_next(events);
          if event.is_null() {
            break
          }
          //handle single event
          match pn_event_type(event) {
            _ => {
              if pn_event_type(event) == pn_event_type_t::PN_DELIVERY {
                println!("got message");
                let delivery = pn_event_delivery(event);
                if pn_delivery_readable(delivery) {
                  let link = pn_delivery_link(delivery);
                  let size = pn_delivery_pending(delivery);
                  let buf_vec:Vec<i8> = vec![0; size];
                  let buf_ref: *const std::os::raw::c_char = buf_vec.as_ptr();
                  let bytes_received = pn_link_recv(link, buf_ref, size);
                  println!("bytes_received: {}",bytes_received);
                  let message = pn_message();
                  let status = pn_message_decode(message, buf_ref, size);
                  if status!=0 {
                    println!("message decoding failed");
                    /* Print the decoded message */
                    // pn_string_t *s = pn_string(NULL);
                    // pn_inspect(pn_message_body(m), s);
                    // printf("%s\n", pn_string_get(s));
                    // pn_free(s);
                    // pn_message_free(m);
                    // free(data.start);
                  }
                  //#define PN_ACCEPTED (0x0000000000000024)
                  pn_delivery_update(delivery, 0x0000000000000024);
                  pn_delivery_settle(delivery);  /* settle and free d */
                  // add more credit
                  pn_link_flow(link, 1);
                }
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
    result
  }
}
impl Connection {
  /// start a consumer
  pub fn open_consumer_link(&self, destination: String) -> Link {
    unsafe{
      let sender_name = "consumer2";
      let c_sender_name = CString::new(sender_name).unwrap();
      let link = pn_receiver(self.session, c_sender_name.as_ptr());
      let c_amqp_address = CString::new(destination).unwrap();
      pn_terminus_set_address(pn_link_source(link), c_amqp_address.as_ptr());
      pn_link_open(link);
      pn_link_flow(link, 1);
      self.wait_for(pn_event_type_t::PN_LINK_FLOW);
      Link{
        link: link,
        proactor: self.proactor,
      }
    }
  }
  /// start a producer
  pub fn open_producer_link(&self, destination: String) -> Link {
    unsafe{
      let sender_name = "sender2";
      let c_sender_name = CString::new(sender_name).unwrap();
      let link = pn_sender(self.session, c_sender_name.as_ptr());
      let c_amqp_address = CString::new(destination).unwrap();
      pn_terminus_set_address(pn_link_target(link), c_amqp_address.as_ptr());
      pn_link_open(link);
      self.wait_for(pn_event_type_t::PN_LINK_FLOW);
      Link{
        link: link,
        proactor: self.proactor,
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

pub fn connect(host: String, port: u16, auth: Option<SaslAuth>) -> Option<Connection> {
  let mut result: Option<Connection> = None;
  unsafe{
    let proactor = pn_proactor();
    let addr = format!("{}:{}",host,port);
    let host2 = host.clone();
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
            result = Some(Connection{
              transport: transport,
              connection: connection,
              proactor: proactor,
              session: s,
            });
            should_continue = false;
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
            panic!("{}: {}",name2,description2);
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

// 
// lib version 2
//

pub fn receive(url: String) {
  unsafe {
    let messenger_name = CString::new("messenger1").unwrap();
    let messenger = pn_messenger(messenger_name.as_ptr());
    let c_url = CString::new(url).unwrap();
    pn_messenger_subscribe(messenger, c_url.as_ptr());
    // >   pn_messenger_rewrite(messenger, "amqp://%/*", "$2");
    // >   pn_messenger_set_incoming_window(messenger, 200);
    // >   pn_messenger_set_blocking(messenger, 1);
    // >   for(;;) {
    // >   {
    let count = pn_messenger_recv(messenger, -1);
    println!("count: {}",count);
  }
}