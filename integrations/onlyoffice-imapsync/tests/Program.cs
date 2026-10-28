using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using ASC.Mail.Enums;
using ASC.Mail.ImapSync;
using ASC.Mail.Models;
using ASC.Mail.Core.Entities;
using MailKit;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis.Extensions.Core.Abstractions;
using MailFolder = ASC.Mail.Models.MailFolder;

// Real service dispatch and per-client guards run against in-memory transport interfaces.
// IMAP task bodies stay Created and are never started. No server/DB is contacted.
public class InterfaceStub : DispatchProxy
{
    public Func<MethodInfo, object[], object> Handler;
    protected override object Invoke(MethodInfo method, object[] args) => Handler(method, args);
}

internal static class Program
{
    private static int checks, failures;
    private static readonly BindingFlags All = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
    private static void Check(bool condition, string label)
    {
        checks++;
        if (!condition) failures++;
        Console.WriteLine((condition ? "PASS " : "FAIL ") + label);
    }

    private static void Field(object instance, string name, object value)
        => instance.GetType().GetField(name, All).SetValue(instance, value);

    private static T Proxy<T>(Func<MethodInfo, object[], object> callback) where T : class
    {
        var result = DispatchProxy.Create<T, InterfaceStub>();
        ((InterfaceStub)(object)result).Handler = callback;
        return result;
    }

    private static SimpleImapClient Client(int mailbox, FolderType folder, params int[] ids)
    {
        var client = (SimpleImapClient)RuntimeHelpers.GetUninitializedObject(typeof(SimpleImapClient));
        var account = (MailBoxData)RuntimeHelpers.GetUninitializedObject(typeof(MailBoxData));
        account.MailBoxId = mailbox;
        var transportFolder = Proxy<IMailFolder>((method, args) => method.Name switch
        {
            "get_FullName" or "get_Name" => folder.ToString(),
            _ => throw new InvalidOperationException("Unexpected IMAP call: " + method.Name)
        });
        Field(client, "Account", account);
        Field(client, "<ImapWorkFolder>k__BackingField", transportFolder);
        Field(client, "foldersDictionary", new Dictionary<IMailFolder, MailFolder>
        {
            [transportFolder] = new MailFolder(folder, folder.ToString())
        });
        Field(client, "asyncTasks", new ConcurrentQueue<Task<bool>>());
        Field(client, "_log", NullLogger.Instance);
        client.ImapMessagesList = ids.Select(id =>
        {
            var message = (MessageDescriptor)RuntimeHelpers.GetUninitializedObject(typeof(MessageDescriptor));
            message.MessageIdInDB = id;
            message.UniqueId = new UniqueId((uint)id);
            message.Flags = MessageFlags.Draft;
            return message;
        }).ToList();
        return client;
    }

    private static ConcurrentQueue<Task<bool>> Tasks(SimpleImapClient client)
        => (ConcurrentQueue<Task<bool>>)typeof(SimpleImapClient).GetField("asyncTasks", All).GetValue(client);

    private static async Task Dispatch(List<SimpleImapClient> clients, params int[] messageIds)
    {
        var pending = new Queue<CashedMailUserAction>(new[]
        {
            new CashedMailUserAction
            {
                Action = MailUserAction.SendDraft,
                Uds = messageIds.ToList(),
                Destination = -1,
                Tenant = 1,
                UserName = "fixture"
            }
        });
        var redisDb = Proxy<IRedisDatabase>((method, args) =>
        {
            if (method.Name != "ListGetFromRightAsync")
                throw new InvalidOperationException("Unexpected Redis DB call: " + method.Name);
            object value = pending.Count == 0 ? null : pending.Dequeue();
            return typeof(Task).GetMethod(nameof(Task.FromResult)).MakeGenericMethod(method.GetGenericArguments())
                .Invoke(null, new[] { value });
        });
        var redisTransport = Proxy<IRedisClient>((method, args) => method.Name == "get_Db0"
            ? redisDb : throw new InvalidOperationException("Unexpected Redis client call: " + method.Name));
        var dispatcher = (MailImapClient)RuntimeHelpers.GetUninitializedObject(typeof(MailImapClient));
        Field(dispatcher, "simpleImapClients", clients);
        Field(dispatcher, "_redisClient", new RedisClient(redisTransport));
        Field(dispatcher, "_log", NullLogger.Instance);
        Field(dispatcher, "RedisKey", "fixture-only");
        await dispatcher.CheckRedis();
        Check(pending.Count == 0, "the real dispatcher consumed the fixture action");
        Check(clients.SelectMany(Tasks).All(task => task.Status == TaskStatus.Created),
            "all queued IMAP tasks remain unstarted");
    }

    private static void RecoveryPredicate()
    {
        // Inspect/invoke the actual compiler-generated selector used by UpdateDraftDbFolder.
        // This exercises that selector without constructing the database engine.
        var candidates = typeof(MailImapClient).Assembly.GetTypes().SelectMany(type => type.GetMethods(All))
            .Where(method => (method.Name.Contains("<UpdateDraftDbFolder>") || method.Name.Contains("<RestoreMissingDrafts>"))
                && method.ReturnType == typeof(bool)
                && method.GetParameters().Length == 1
                && method.GetParameters()[0].ParameterType == typeof(SimpleImapClient)).ToList();
        Check(candidates.Count == 1, "one actual Sent-folder recovery selector is identified");
        if (candidates.Count != 1) return;
        var predicate = candidates[0];
        var holder = predicate.IsStatic ? null : RuntimeHelpers.GetUninitializedObject(predicate.DeclaringType);
        if (holder != null)
            foreach (var field in predicate.DeclaringType.GetFields(All).Where(field => field.FieldType == typeof(SimpleImapClient)))
                field.SetValue(holder, Client(22, FolderType.Draft, 901));
        bool Match(SimpleImapClient client) => (bool)predicate.Invoke(holder, new object[] { client });
        Check(!Match(Client(21, FolderType.Sent, 901)), "recovery excludes another mailbox's Sent folder");
        Check(Match(Client(22, FolderType.Sent, 901)), "recovery selects the sending mailbox's Sent folder");
        Check(!Match(Client(22, FolderType.Draft, 901)), "recovery excludes a Draft folder in the same mailbox");
    }

    private static void RecoveryFlow()
    {
        var restoreMethod = typeof(MailImapClient).GetMethod("RestoreMissingDrafts", All);
        var retryMethod = typeof(MailImapClient).GetMethod("RetryDraftRecoveryForSentClient", All);
        Check(restoreMethod != null && retryMethod != null, "the real recovery and readiness flow are available");
        if (restoreMethod == null || retryMethod == null) return;
        var otherDraft = Client(21, FolderType.Draft, 801);
        var ownDraft = Client(22, FolderType.Draft, 901);
        var unloadedDraft = Client(22, FolderType.Draft, 903);
        unloadedDraft.ImapMessagesList = null;
        var otherSent = Client(21, FolderType.Sent, 901, 902);
        otherSent.ImapMessagesList[0].IMAPMessageId = "sent-example";
        otherSent.ImapMessagesList[1].IMAPMessageId = "unsent-example";
        var clients = new List<SimpleImapClient> { otherDraft, ownDraft, unloadedDraft, otherSent };
        var dispatcher = (MailImapClient)RuntimeHelpers.GetUninitializedObject(typeof(MailImapClient));
        Field(dispatcher, "simpleImapClients", clients);
        Field(dispatcher, "deferredDraftRecovery", new ConcurrentDictionary<int, byte>());
        var pending = new List<MailInfo>
        {
            new MailInfo { Id = 901, MimeMessageId = "sent-example" },
            new MailInfo { Id = 902, MimeMessageId = "unsent-example" }
        };
        var restored = new List<CashedMailUserAction>();
        var retried = new List<SimpleImapClient>();
        Action<CashedMailUserAction> capture = action => restored.Add(action);
        void Restore(SimpleImapClient client) => restoreMethod.Invoke(dispatcher, new object[] { client, pending, capture });
        Action<SimpleImapClient> reconcile = client => { retried.Add(client); Restore(client); };
        void Retry(SimpleImapClient client) => retryMethod.Invoke(dispatcher, new object[] { client, reconcile });

        Restore(ownDraft);
        Check(restored.Count == 0, "missing own Sent defers restoration despite another mailbox being ready");
        Check(pending.Select(mail => mail.Id).SequenceEqual(new[] { 901, 902 }), "deferred pending drafts remain intact");
        Retry(otherSent);
        Check(retried.Count == 0 && restored.Count == 0, "another mailbox becoming ready cannot release deferred recovery");

        var ownSent = Client(22, FolderType.Sent, 901);
        ownSent.ImapMessagesList = null;
        clients.Add(ownSent);
        Restore(ownDraft);
        Retry(ownSent);
        Check(restored.Count == 0 && retried.Count == 0, "an unloaded own Sent list neither restores nor retries");

        // Reconnect creates the replacement before removing the old unloaded client.
        ownSent = Client(22, FolderType.Sent, 901);
        clients.Add(ownSent);
        ownSent.ImapMessagesList[0].IMAPMessageId = "sent-example";
        Retry(ownSent);
        Check(retried.SequenceEqual(new[] { ownDraft }), "Sent readiness retries only the same mailbox's loaded Draft client");
        Check(restored.Count == 1 && restored[0].Uds.SequenceEqual(new[] { 902 }), "ready Sent suppresses the sent copy and restores only the genuinely missing draft");
        Check(restored.Count == 1, "an earlier unloaded Sent client cannot hide its loaded replacement");
        Check(restored.All(action => action.Action == MailUserAction.UpdateDrafts), "recovery emits only draft-update actions, never a send action");
        Retry(ownSent);
        Check(retried.Count == 1 && restored.Count == 1, "a consumed deferred marker prevents a redundant readiness retry");

        restored.Clear();
        ownSent.ImapMessagesList.Add(Client(22, FolderType.Sent, 902).ImapMessagesList[0]);
        ownSent.ImapMessagesList[1].IMAPMessageId = "unsent-example";
        Restore(ownDraft);
        Check(restored.Count == 0, "filtering all pending drafts as already sent invokes no restore callback");

        ownSent.ImapMessagesList.Clear();
        Restore(ownDraft);
        Check(restored.Count == 1 && restored[0].Uds.SequenceEqual(new[] { 901, 902 }), "a known empty own Sent list allows legitimate draft recovery");
        Check(Tasks(ownDraft).IsEmpty && Tasks(otherDraft).IsEmpty, "recovery fixture executes no IMAP tasks");
    }

    private static async Task EngineLockFlow()
    {
        var withLock = typeof(MailImapClient).GetMethod("WithEngineLock", All);
        var complete = typeof(MailImapClient).GetMethod("CompleteFolderUpdate", All);
        Check(withLock != null && complete != null, "the real shared-engine lock helpers are available");
        if (withLock == null || complete == null) return;
        var dispatcher = (MailImapClient)RuntimeHelpers.GetUninitializedObject(typeof(MailImapClient));
        using var semaphore = new SemaphoreSlim(1, 1);
        Field(dispatcher, "_enginesFactorySemaphore", semaphore);
        using var entered = new ManualResetEventSlim();
        using var finish = new ManualResetEventSlim();
        bool ownedDuringAction = false;
        var operation = Task.Run(() => withLock.Invoke(dispatcher, new object[] { (Action)(() =>
        {
            ownedDuringAction = semaphore.CurrentCount == 0;
            entered.Set();
            if (!finish.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Fixture release was not signalled");
        }) }));
        try
        {
            Check(entered.Wait(TimeSpan.FromSeconds(5)), "a real engine operation entered its guarded callback");
            Check(ownedDuringAction, "folder initialization holds the shared engine permit");
            bool overlappingEntry = semaphore.Wait(0);
            if (overlappingEntry) semaphore.Release();
            Check(!overlappingEntry, "another operation cannot enter while folder initialization owns the context");
        }
        finally
        {
            finish.Set();
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Check(semaphore.CurrentCount == 1, "successful folder initialization releases exactly its own permit");

        var failure = new InvalidOperationException("fixture engine failure");
        bool sameFailure = false;
        try { withLock.Invoke(dispatcher, new object[] { (Action)(() => throw failure) }); }
        catch (TargetInvocationException ex) { sameFailure = ReferenceEquals(ex.InnerException, failure); }
        Check(sameFailure, "a failing engine operation retains its original exception");
        Check(semaphore.CurrentCount == 1, "a failing engine operation still releases exactly one permit");

        semaphore.Wait();
        bool recalcOwned = false, recalcBlockedOther = false;
        complete.Invoke(dispatcher, new object[] { (Action)(() =>
        {
            recalcOwned = semaphore.CurrentCount == 0;
            bool entry = semaphore.Wait(0);
            recalcBlockedOther = !entry;
            if (entry) semaphore.Release();
        }) });
        Check(recalcOwned && recalcBlockedOther, "reconciliation retains exclusive context ownership through recalculation");
        Check((bool)typeof(MailImapClient).GetField("needUserUpdate", All).GetValue(dispatcher),
            "completing a folder update retains the normal user-update signal");
        Check(semaphore.CurrentCount == 1, "successful recalculation releases the existing reconciliation permit");

        semaphore.Wait();
        sameFailure = false;
        try { complete.Invoke(dispatcher, new object[] { (Action)(() => throw failure) }); }
        catch (TargetInvocationException ex) { sameFailure = ReferenceEquals(ex.InnerException, failure); }
        Check(sameFailure, "recalculation failure is preserved for the existing caller handling");
        Check(semaphore.CurrentCount == 1, "recalculation failure cannot strand the shared semaphore");
    }

    private static void EnginePermitOwnership()
    {
        var dispatcher = (MailImapClient)RuntimeHelpers.GetUninitializedObject(typeof(MailImapClient));
        using var semaphore = new SemaphoreSlim(1, 1);
        Field(dispatcher, "_enginesFactorySemaphore", semaphore);
        Field(dispatcher, "_log", NullLogger.Instance);
        Field(dispatcher, "simpleImapClients", new List<SimpleImapClient>());
        var account = (MailBoxData)RuntimeHelpers.GetUninitializedObject(typeof(MailBoxData));
        account.MailBoxId = 22;
        account.EMail = new System.Net.Mail.MailAddress("fixture@example.invalid");
        var create = typeof(MailImapClient).GetMethod("CreateSimpleImapClients", All);
        var delete = typeof(MailImapClient).GetMethod("DeleteSimpleImapClients", All);
        semaphore.Wait();
        // _cancelToken is deliberately null: argument evaluation fails before
        // any SimpleImapClient is constructed or any transport can be reached.
        create.Invoke(dispatcher, new object[] { account });
        Check(semaphore.CurrentCount == 0, "creation failure before Wait cannot release another callback's permit");
        if (semaphore.CurrentCount == 0) semaphore.Release();

        Field(dispatcher, "simpleImapClients", new List<SimpleImapClient> { null });
        semaphore.Wait();
        // The malformed local fixture fails during selection, before Stop/Wait.
        delete.Invoke(dispatcher, new object[] { account });
        Check(semaphore.CurrentCount == 0, "deletion failure before Wait cannot release another callback's permit");
        if (semaphore.CurrentCount == 0) semaphore.Release();

        Field(dispatcher, "simpleImapClients", new List<SimpleImapClient>());
        // No clients exist to stop; the null factory fails only after Wait.
        delete.Invoke(dispatcher, new object[] { account });
        Check(semaphore.CurrentCount == 1, "deletion failure after Wait releases its own permit");
    }

    private static async Task<int> Main(string[] args)
    {
        var first = Client(21, FolderType.Draft, 801);
        var second = Client(22, FolderType.Draft, 901);
        var sent = Client(22, FolderType.Sent, 901);
        await Dispatch(new() { first, second, sent }, 901);
        Check(Tasks(second).Count == 1, "send from the second mailbox queues its Draft cleanup");
        Check(Tasks(first).Count == 0, "another mailbox's unsent draft is untouched");
        Check(Tasks(sent).Count == 0, "the successful Sent copy is untouched");

        first = Client(21, FolderType.Draft, 801);
        second = Client(22, FolderType.Draft, 901);
        await Dispatch(new() { second, first }, 901);
        Check(Tasks(second).Count == 1 && Tasks(first).Count == 0, "mailbox ordering does not change cleanup ownership");

        first = Client(21, FolderType.Draft, 801);
        second = Client(22, FolderType.Draft, 901);
        await Dispatch(new() { first, second }, 801, 901);
        Check(Tasks(first).Count == 1 && Tasks(second).Count == 1, "a multi-ID action reaches both owning Draft mailboxes");

        first = Client(21, FolderType.Draft, 801);
        second = Client(22, FolderType.Draft, 901);
        await Dispatch(new() { first, second }, 999);
        Check(Tasks(first).IsEmpty && Tasks(second).IsEmpty, "an unknown message ID cannot clean up another draft");

        first = Client(21, FolderType.Draft, 801);
        first.ImapMessagesList = null;
        second = Client(22, FolderType.Draft, 901);
        await Dispatch(new() { first, second }, 901);
        Check(Tasks(first).IsEmpty && Tasks(second).Count == 1, "an unloaded first mailbox does not block the matching loaded mailbox");

        await Dispatch(new(), 901);
        Check(true, "no Draft clients is handled without a transport operation");
        RecoveryPredicate();
        if (!args.Contains("--dispatch-only"))
        {
            RecoveryFlow();
            await EngineLockFlow();
            EnginePermitOwnership();
        }
        Console.WriteLine($"Checks {checks}; failures {failures}; network operations 0; IMAP tasks started 0");
        return failures == 0 ? 0 : 1;
    }
}
