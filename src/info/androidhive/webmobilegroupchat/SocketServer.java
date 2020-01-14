package info.androidhive.webmobilegroupchat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.sql.*;

import javax.websocket.OnClose;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import org.json.JSONException;
import org.json.JSONObject;
import com.google.common.collect.Maps;
import cn.edu.buaa.crypto.utils.Base64Util;
import cn.edu.buaa.crypto.utils.ZipUtils;

//该注解用来指定一个URI，客户端可以通过这个URI来连接到WebSocket。
@ServerEndpoint("/chat")
public class SocketServer {
 
    // set to store all the live sessions
    private static final Set<Session> sessions = Collections
            .synchronizedSet(new HashSet<Session>());
 
    // Mapping between session and person name
    private static final HashMap<String, String> nameSessionPair = new HashMap<String, String>();
    
    // Mapping between session and person groupId
    private static final HashMap<String, Integer> groupSessionPair = new HashMap<String, Integer>();
 
    private JSONUtils jsonUtils = new JSONUtils();
	SqliteHelper h;
    String repostFileName = null;
    String ckksFileName = null;
    
    // Getting query params
    public static Map<String, String> getQueryMap(String query) {
        Map<String, String> map = Maps.newHashMap();
        if (query != null) {
            String[] params = query.split("&");
            for (String param : params) {
                String[] nameval = param.split("=");
                map.put(nameval[0], nameval[1]);
            }
        }
        return map;
    }
    
 
    /**
     * Called when a socket connection opened
     *  session :与某个客户端的连接会话，需要通过它来给客户端发送数据
     * */
    @OnOpen
    public void onOpen(Session session) {
        System.out.println(session.getId() + " 打开一个会话");
 
        Map<String, String> queryParams = getQueryMap(session.getQueryString());
 
        String name = "";
        String gId = "";
        int groupId = 0;
        
        if (queryParams.containsKey("name")) {//true
            // Getting client name via query param
            name = queryParams.get("name");
            try {
                name = URLDecoder.decode(name, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
 
            // Mapping client name and session id
            nameSessionPair.put(session.getId(), name);
        }
        
        if (queryParams.containsKey("groupId")) {
        	 
            // Getting client groupId via query param
            gId = queryParams.get("groupId");
            try {
                groupId = Integer.parseInt(URLDecoder.decode(gId, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
 
            // Mapping client groupId and session id
            groupSessionPair.put(session.getId(), groupId);
        }
        
 
        // Adding session to session list
        sessions.add(session);
        
        //来一个用户加入数据库
        try {
			h = new SqliteHelper("E:\\Program\\eclipse-workplace\\WebMobileGroupChatServer\\test.db");
			//select count(*) from table where 字段 = ""; //符合该条件的记录总数
//			String selectsql =  "select count(*) from user"
//					 +"'where name='"
//   					 +nameSessionPair.get(session.getId())
//   					 +"'and groupId="
//   					 +groupSessionPair.get(session.getId());
//			ResultSetExtractor rse = null;
//			int count = h.executeQuery(selectsql, rse);
			
			String insertsql = "insert into user(sessionId,name,groupId) values('"+session.getId()+"','"
	  			 		+nameSessionPair.get(session.getId())+"',"
	  			 		+groupSessionPair.get(session.getId())+")";
			// String sql = "insert into user values(1,'Ali',1,'1565139872132')";
		    System.out.println(insertsql);
				 
		    h.executeUpdate(insertsql);
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch (SQLException e1) {
			e1.printStackTrace();
		}
    	
 
        try {
            // Sending session id to the client that just connected
            session.getBasicRemote().sendText(
                    jsonUtils.getClientDetailsJson(session.getId(),
                            "你的session"));
        } catch (IOException e) {
            e.printStackTrace();
        }
 
        // Notifying all the clients about new person joined
        sendMessageToAll(session.getId(), name, groupId, " 加入群聊!", 0, "", true,
                false);
 
    }
 
    /**
     * method called when new message received from any client
     * @param message
     * JSON message from client
     * @throws IOException 
     * */
    @OnMessage
    public void onMessage(String message, Session session) throws IOException{	
        System.out.println("消息来自： " + session.getId() + ": " + message);
 
        String msg = null;
        int type = 0;

        String ukFile = null;
        int repostGroupId = 0;
    	String basicDir = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images";
        String basicPath = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images\\CKKS";
 
        try {
            JSONObject jObj = new JSONObject(message);
            type = jObj.getInt("type");
           
            if(type == 1) { //图片(文件名)消息, 存储在数据库中
            	msg = jObj.getString("message");
	            //将图片存入数据库
	            try{
	             h = new SqliteHelper("E:\\Program\\eclipse-workplace\\WebMobileGroupChatServer\\test.db");    	
	   			 String updatesql = "update user set fileName= '"+ msg
	   					 +"'where name='"
	   					 +nameSessionPair.get(session.getId())
	   					 +"'and groupId="
	   					 +groupSessionPair.get(session.getId());
	   			 
	   			// String sql = "insert into user values(1,'Ali',1,'1565139872132')";
	   			 System.out.println(updatesql);	   			 
	   			 h.executeUpdate(updatesql);	   			 
	   			
	          } catch (ClassNotFoundException e) {
	                e.printStackTrace();
	          } catch (SQLException e) {
	                e.printStackTrace();
	          }
	                      	            
				//拼接url
				//msg= "http://10.112.159.87:8080/images/"+fileName;
				//System.out.println("图片的url："+msg);
	            // Sending the message to all clients
	            sendMessageToAll(session.getId(), nameSessionPair.get(session.getId()),groupSessionPair.get(session.getId()),
	                    msg, type, msg, false, false);           
	            
            }else if(type == 2 || type == 6) {//文本消息
            	msg = jObj.getString("message");
            	  sendMessageToAll(session.getId(), nameSessionPair.get(session.getId()),groupSessionPair.get(session.getId()),
  	                    msg,type,"",false, false);
            }else if(type == 3) {//转发消息
            	//接收更新密钥
            	ukFile = jObj.getString("ukFile");
            	System.out.println(ukFile);
		    	//字符串Base64解码后写入文件MHOO_UK.txt
		    	Base64Util.String2File(ukFile, basicDir + "\\MHOO_UK.txt"); 	

            	//转发到的目标群聊
            	repostGroupId = jObj.getInt("groupId");
            	
            	String querysql ="select groupId from user where name ='"+ nameSessionPair.get(session.getId())+"'";
            	//转发前要判断转发者是不是在目标群聊里
            	try {
					List<String> grouplist = h.executeQuery(querysql, new RowMapper<String>() {
					     @Override
					     public String mapRow(ResultSet rs, int index)
					             throws SQLException {
					         return rs.getString("groupId");
					     }
					 });
					System.out.println(grouplist.contains(repostGroupId+""));
				     if(grouplist.contains(repostGroupId+"")) {
				    	//TODO:将MHOO_UK.txt上传至 CloudServer
				    	System.out.println("开始上传MHOO_UK.txt");	 
		                Thread thread = new Thread(new Runnable(){
		                    @Override
		                    public void run() {
		                        Client client = null; // 启动客户端连接，上传文件
		                        try {
		                            client = new Client(8126);
		                            repostFileName = client.uploadUK("MHOO_UK.txt"); // 上传更新密钥MHOO_UK.txt
		                            client.close();
		                        } catch (IOException e) {
		                            e.printStackTrace();
		                        }
		                    }
		                });
		                thread.start();
		                try {
		                    thread.join();
		                } catch (InterruptedException e) {
		                    e.printStackTrace();
		                }
		                System.out.println("MHOO_UK.txt上传完成");	   
		                System.out.println("转发图片名(tag)："+ repostFileName);	 
				    	//TODO:将从CloudServer接收到的文件名（tag）发送至Group
		                sendMessageToAll(session.getId(), nameSessionPair.get(session.getId()),repostGroupId,
		                		repostFileName,type,"",false, false);
				     }
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				} catch (SQLException e) {
					e.printStackTrace();
				}      	
            }
            else if(type == 4){ //加密人脸特征，返回人脸识别的id
            	//接收到sender的人脸特征，外包给CloudServer同态计算，获得加密的距离，解密开方<1.1, fti = wi.id
            	msg = jObj.getString("message");
            	String name = nameSessionPair.get(session.getId());
                int groupId = groupSessionPair.get(session.getId());
                
                try {
					Thread.sleep(2000);
				} catch (InterruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
                //TODO:Cloud-assisted Face Recognition by Social Provider
                //向CloudServer请求加密特征的同态计算值，从文件读密文，先解密 -> double值求和 ->开平方
                System.out.println("---------开始请求下载zip--------");
                Thread thread = new Thread(new Runnable(){
                    @Override
                    public void run() {
                        Client client = null; // 启动客户端连接，下载文件
                        try {
                            client = new Client(8125);
                            ckksFileName = client.downloadFile("FR.zip"); // 上传更新密钥MHOO_UK.txt
                            client.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                });
                thread.start();
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                System.out.println("----------zip下载完成--------");
                
            	//将从客户端接受的消息写入文件        
				String unzipPath = basicDir + "\\" + String.valueOf(ckksFileName);
				File unZip = new File(unzipPath);
				if(!unZip.exists()) {         		
					unZip.mkdirs();
            	}
				ZipUtils.unZip(new File(unzipPath+".zip"), unzipPath);
				System.out.println("压缩包路径：" + unzipPath +".zip");
				System.out.println("解压缩包路径：" + unZip.getPath());
	            System.out.println("---------结束--------");				
				
				
				
				//TODO:解密、求和、开方、比较
                System.out.println(System.getProperty("java.library.path"));
                System.loadLibrary("jni_CKKS");//jni规范的so库
                //System.load("D:\\gitSpace\\DLL_lib\\jni_CKKS.dll");
                
                //String couserIds = JniUtils.FR(basicDir, basicPath);
                String couserIds = JniUtils.FR(basicDir, unzipPath);
                System.out.println("人脸识别结果：" + couserIds);
                //String couserIds ="0:Bob;1:Ali";
            	//String json = jsonUtils.getSendAllMessageJson(session.getId(), name, groupId, couserIds, type, "");
            	String json = jsonUtils.getSendAllMessageJson(session.getId(), "Social Provider", groupId, couserIds, type, "");
            	System.out.println("发送消息给: " + session.getId()+ ", "
                         + json);
  
                session.getBasicRemote().sendText(json);     

            } else if(type == 5){//从Sender接收，通知用户重新下载photo.zip
            	msg = jObj.getString("message");
            	sendMessageToAll(session.getId(), nameSessionPair.get(session.getId()),groupSessionPair.get(session.getId()),
	                    msg, type,"",false, false);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }catch (IOException e) {
            System.out.println("error in sending. " + session.getId() + ", "
                    + e.getMessage());
            e.printStackTrace();
        }
 
        // Sending the message to all clients
//        sendMessageToAll(session.getId(), nameSessionPair.get(session.getId()),groupSessionPair.get(session.getId()),
//                msg,type, false, false);
    }
 
    /**
     * Method called when a connection is closed
     * */
    @OnClose
    public void onClose(Session session) {
 
        System.out.println("Session " + session.getId() + " 结束");
 
        // Getting the client name that exited
        String name = nameSessionPair.get(session.getId());
        int groupId = groupSessionPair.get(session.getId());
        // removing the session from sessions list
        sessions.remove(session);
 
        // Notifying all the clients about person exit
        sendMessageToAll(session.getId(), name, groupId, " 离开群聊", 0, "",false,
                true);
 
    }
 
    /**
     * Method to send message to all clients
     * @param sessionId
     * @param message: message to be sent to clients
     * @param isNewClient:flag to identify that message is about new person joined
     * @param isExit: flag to identify that a person left the conversation
     * */
    private void sendMessageToAll(String sessionId, String name, int groupId,
            String message,int type,String fileName, boolean isNewClient, boolean isExit) {
    	//获得在当前group的在线人数
    	int onlineCountInGroup=0;
    	for(Session s: sessions) {
    		if(groupSessionPair.get(s.getId()).equals(groupId)) {
    			onlineCountInGroup++;
        	}
    	}
    
        // Looping through all the sessions and sending the message individually
        for (Session s : sessions) {
        	if(groupSessionPair.get(s.getId()).equals(groupId)) {//发送到指定的group
        		  String json = null;
                  // Checking if the message is about new client joined
                  if (isNewClient) {
                      json = jsonUtils.getNewClientJson(sessionId, name, groupId, message,
                              onlineCountInGroup);
       
                  } else if (isExit) {
                      // Checking if the person left the conversation
                      json = jsonUtils.getClientExitJson(sessionId, name, groupId, message,
                    		  onlineCountInGroup);
                  } else {
                      // Normal chat conversation message
                      json = jsonUtils
                              .getSendAllMessageJson(sessionId, name, groupId, message,type,fileName);
                  }
       
                  try {
                      System.out.println("发送消息给: " + sessionId + ", "
                              + json);
       
                      s.getBasicRemote().sendText(json);
                      
                  } catch (IOException e) {
                      System.out.println("error in sending. " + s.getId() + ", "
                              + e.getMessage());
                      e.printStackTrace();
                  }
        	}
          
        }
    }
    
    
    
    
}