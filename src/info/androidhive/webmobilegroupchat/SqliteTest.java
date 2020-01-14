package info.androidhive.webmobilegroupchat;


import java.sql.*;
import java.util.List;
//import org.sqlite.JDBC;
/**
 * 这是个非常简单的SQLite的Java程序,
 * 程序中创建数据库、创建表、然后插入数据，最后读出数据显示出来
 */
public class SqliteTest 
{
    public static void main(String[] args) {
        try{
			 SqliteHelper h = new SqliteHelper("test.db");
			 h.executeUpdate("drop table if exists user;");
   			 h.executeUpdate("create table user (id integer primary key autoincrement, sessionId integer, name string, groupId integer, fileName string)");   			 		
 			System.out.println("test.db sucessful!");
        } catch (ClassNotFoundException e) {
             e.printStackTrace();
       } catch (SQLException e) {
             e.printStackTrace();
       }
    }
}

