package a.springboot.security.model;

public class Message {
	
	private String content;

	public Message(String content) {
		this.setContent(content);
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}
}
