
fn main() {
  let host = "testservicebus12345.servicebus.windows.net".to_string();
  let port = 5671;
  let auth = qpid_proton::SaslAuth{
    username: "RootManageSharedAccessKey".to_string(),
    password: "Hgg+bSZstkJIqhRpjixF+fSUj".to_string()
  };
  let queue = "myqueue".to_string();
  let connection = qpid_proton::connect(host,port,Some(auth),queue);

  match connection {
    Some(connection) => {
      connection.send_message("hallo welt".to_string());
    },
    None => {
      println!("connect failed.");
    }
  }
  println!("done.")
}