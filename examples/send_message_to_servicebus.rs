use qpid_proton::*;

fn main() {
  let host = "servicebus4infrastructurecore.servicebus.windows.net".to_string();
  let port = 5671;
  let auth = SaslAuth{
    username: "RootManageSharedAccessKey".to_string(),
    password: "Hgg+bSZstkJIqhRpjixF+fSUjs+seRrsPvyMJFtrpuI=".to_string()
  };
  let queue = "myqueue".to_string();
  let connection = connect(host,port,Some(auth),queue);

  match connection {
    Some(connection) => {
      send_message(connection,"hallo welt".to_string());
    },
    None => {
      println!("connect failed.");
    }
  }
  println!("done.")
}