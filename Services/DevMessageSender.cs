namespace boilerplate.Api.Services;

public class DevMessageSender : IMessageSender
{
    private readonly ILogger<DevMessageSender> _logger;

    public DevMessageSender(ILogger<DevMessageSender> logger)
    {
        _logger = logger;
    }

    public Task SendEmailAsync(string toEmail, string subject, string body)
    {
        _logger.LogWarning("DEV EMAIL STUB\nTo: {To}\nSubject: {Subject}\nBody:\n{Body}", toEmail, subject, body);
        return Task.CompletedTask;
    }

    public Task SendSmsAsync(string toPhone, string message)
    {
        _logger.LogWarning("DEV SMS STUB\nTo: {To}\nMessage:\n{Message}", toPhone, message);
        return Task.CompletedTask;
    }
}
