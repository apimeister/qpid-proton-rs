use std::os::raw::c_char;
use std::ffi::CString;
use std::ffi::CStr;
use qpid_proton::*;
use qpid_proton_sys::*;

fn main() {
  unsafe{
    let message = pn_message();
    let proactor = pn_proactor();
    let addr = "testservicebus12345.servicebus.windows.net:5671";

    //char * address = (char *) "amqps://{SAS Key Name}:{SAS key}@{namespace name}.servicebus.windows.net/{event hub name}";
    //char * msgtext = (char *) "Hello from C!";
    let c_addr = CString::new(addr).unwrap();
    // let transport: *mut pn_transport_t = std::ptr::null_mut();
    let transport = pn_transport();
    //enable logging
    let logger = pn_transport_logger(transport);
    // pn_logger_set_mask(logger, pn_log_subsystem_t::PN_SUBSYSTEM_ALL, pn_log_level_t::PN_LEVEL_ALL);
    pn_transport_require_auth(transport,true);
    pn_transport_require_encryption(transport,true);
    let connection = pn_connection();
    // let user = "admin";
    // let password = "admin";
    let user = "RootManageSharedAccessKey";
    let password = "Hgg+bSZstkJIqhRpjixF+fSUj";
    // let password = "SGdnK2JTWnN0a0pJcWhScGppeEYrZlNVanMrc2VScnNQdnlNSkZ0cnB1ST0=";
    pn_connection_set_user(connection, CString::new(user).unwrap().as_ptr());
    pn_connection_set_password(connection, CString::new(password).unwrap().as_ptr());
    pn_connection_set_hostname(connection, CString::new("testservicebus12345.servicebus.windows.net").unwrap().as_ptr());
    let sasl = pn_sasl(transport);
    pn_sasl_set_allow_insecure_mechs(sasl, true);
    pn_sasl_allowed_mechs(sasl, CString::new("PLAIN").unwrap().as_ptr());

    pn_proactor_connect2(proactor,connection, transport, c_addr.as_ptr());
    let mut counter: i64 = 0;
    loop {
      let events = pn_proactor_wait(proactor);
      let mut should_continue = true;
      loop {
        let e = pn_event_batch_next(events);
        if e.is_null() {
          break
        }
        should_continue = handle_event(e, transport, message, &mut counter);
      }
      if !should_continue {
        break;
      }
      pn_proactor_done(proactor, events);
    }
    pn_proactor_free(proactor);  
    pn_message_free(message);
  }
  println!("done.");
}

fn handle_event(event: *mut pn_event_t, transport: *mut pn_transport_t, message: *mut pn_message_t, counter: &mut i64) -> bool {
  unsafe{
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
        pn_ssl_set_peer_hostname(ssl,CString::new("servicebus4infrastructurecore.servicebus.windows.net").unwrap().as_ptr());
        pn_connection_open(c);
        pn_session_open(s);
        let sender_name = "sender";
        let c_sender_name = CString::new(sender_name).unwrap();
        let l = pn_sender(s, c_sender_name.as_ptr());
        let amqp_address = "myqueue";
        let c_amqp_address = CString::new(amqp_address).unwrap();
        pn_terminus_set_address(pn_link_target(l), c_amqp_address.as_ptr());
        pn_link_open(l);
      },
      pn_event_type_t::PN_CONNECTION_REMOTE_OPEN =>{
        let ssl = pn_ssl(transport);
        pn_ssl_set_peer_hostname(ssl,CString::new("servicebus4infrastructurecore.servicebus.windows.net").unwrap().as_ptr());
        let subject = pn_ssl_get_remote_subject(ssl);
        let subject_string = CStr::from_ptr(subject).to_str().unwrap();
        println!("ssl subject: {}",subject_string);
      },
      pn_event_type_t::PN_TRANSPORT_ERROR =>{
        println!("PN_TRANSPORT_ERROR: something went wrong");
        let condition = pn_transport_condition(transport);
        let name = pn_condition_get_name(condition);
        let name2 = CStr::from_ptr(name).to_str().unwrap();
        let description = pn_condition_get_description(condition);
        let description2 = CStr::from_ptr(description).to_str().unwrap();
        println!("name: {}",name2);
        println!("desc: {}",description2);
      },
      pn_event_type_t::PN_LINK_FLOW =>{
        println!("PN_LINK_FLOW: ready for transfer");
        /* The peer has given us some credit, now we can send messages */
        let link = pn_event_link(event);
        
        while pn_link_credit(link) > 0 && *counter == 0 {
          println!("sending msg: {}",counter);
          let counter_string = CString::new(counter.to_string()).unwrap();
          let dtag = pn_dtag(counter_string.as_ptr(), 1);
          pn_delivery(link, dtag);
          pn_message_clear(message);
          let body = pn_message_body(message);
          pn_data_enter(body);
          let content = CString::new("sequence").unwrap();
          pn_data_put_string(body, pn_bytes(8, content.as_ptr()));
          pn_data_exit(body);
          let mut buf_size: usize = 200;
          let buf_vec:Vec<i8> = vec![0; buf_size];
          let buf_ref: *const std::os::raw::c_char = buf_vec.as_ptr();
          let result = pn_message_encode(message,buf_ref,&mut buf_size);
          println!("pn_message_encode: {}",result);
          println!("buffer size {}",buf_size);
          // println!("buffer {:?}",buf_vec);
          let result = pn_link_send(link, buf_ref, buf_size);
          println!("pn_link_send: {}",result);
          let result = pn_link_advance(link);
          println!("pn_link_advance: {}",result);
          *counter= *counter + 1;
          break;
        }
      },
      pn_event_type_t::PN_DELIVERY =>{
        println!("PN_DELIVERY: acknowledged");
        /* We received acknowledgement from the peer that a message was delivered. */
        let delivery = pn_event_delivery(event);
        //PN_ACCEPTED = 0x0000000000000024
        if pn_delivery_remote_state(delivery) == 0x0000000000000024 {
          println!("messages sent and acknowledged");
          pn_connection_close(pn_event_connection(event));
          /* Continue handling events till we receive TRANSPORT_CLOSED */
        } else {
          println!("unexpected delivery state {:?}", pn_delivery_remote_state(delivery));
          pn_connection_close(pn_event_connection(event));
        }
      }
      pn_event_type_t::PN_PROACTOR_INACTIVE =>{
        return false;
      },
      pn_event_type_t::PN_LINK_REMOTE_CLOSE =>{
        println!("PN_LINK_REMOTE_CLOSE: closing connection");
        let event_session = pn_event_session(event);
        let condition = pn_session_remote_condition(event_session);
        // let desc = pn_condition_get_description(condition);
        // let desc2 = CStr::from_ptr(desc).to_str().unwrap();
        // let name = pn_condition_get_name(condition);
        // let name2 = CStr::from_ptr(name).to_str().unwrap();
        // println!("{}",name2);
        // println!("{}",desc2);
        pn_connection_close(pn_event_connection(event));
        return false;
      },
      _ => {
        println!("{:?}",pn_event_type(event));
      }
    }
  }
  return true;
}
