namespace boilerplate.Api.Services;

public interface IMessageSender
{
    Task SendEmailAsync(string toEmail, string subject, string body);
    Task SendSmsAsync(string toPhone, string message);
}
