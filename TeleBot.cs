using System.DirectoryServices.AccountManagement;
using Telegram.Bot;

namespace MyTelegramBot;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly TelegramBotClient _botClient;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        string botToken = "BotToken";
        _botClient = new TelegramBotClient(botToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Notifier Service is starting.");

        while (!stoppingToken.IsCancellationRequested)
        {
            long targetChatId = "chatId";
            
            // Get the machine name
            var machineName = Environment.MachineName;

            // --- NEW: Get a list of all local users ---
            string allUsers = "N/A";
            try
            {
                using (var context = new PrincipalContext(ContextType.Machine))
                {
                    using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                    {
                        var userPrincipals = searcher.FindAll().Cast<UserPrincipal>();
                        // We filter out disabled accounts and only take the names
                        var userNames = userPrincipals.Where(p => p.Enabled == true).Select(p => p.SamAccountName);
                        allUsers = string.Join(", ", userNames);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve user list.");
                allUsers = "Error retrieving users.";
            }
            // -----------------------------------------

            // Create the new message format
            string messageToSend = $"Service update from machine: '{machineName}'\n with users being {allUsers}\n  at Time: {DateTime.Now:F}";

            try
            {
                await _botClient.SendTextMessageAsync(
                    chatId: targetChatId,
                    text: messageToSend,
                    cancellationToken: stoppingToken);
                
                _logger.LogInformation("Message sent successfully from {MachineName}", machineName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send scheduled message from {MachineName}", machineName);
            }

            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
        }
    }
}
