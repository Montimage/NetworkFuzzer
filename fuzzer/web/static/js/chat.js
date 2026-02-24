/* Alpine.js chat component for the NetworkFuzzer agent. */

function chatApp() {
    return {
        messages: JSON.parse(localStorage.getItem('nf_chat') || '[]'),
        input: '',
        loading: false,
        sessionId: localStorage.getItem('nf_session') || crypto.randomUUID(),

        init() {
            localStorage.setItem('nf_session', this.sessionId);
            this.$nextTick(() => this.scrollToBottom());
        },

        async send() {
            const text = this.input.trim();
            if (!text || this.loading) return;

            this.messages.push({ role: 'user', content: text });
            this.input = '';
            this.loading = true;
            this.save();
            this.scrollToBottom();

            try {
                const resp = await fetch('/ui/agent/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: text,
                        session_id: this.sessionId,
                    }),
                });
                const data = await resp.json();
                if (data.messages) {
                    for (const msg of data.messages) {
                        this.messages.push(msg);
                    }
                }
            } catch (err) {
                this.messages.push({
                    role: 'assistant',
                    content: 'Connection error: ' + err.message,
                });
            }

            this.loading = false;
            this.save();
            this.scrollToBottom();
        },

        save() {
            // Keep last 200 messages in localStorage
            const toSave = this.messages.slice(-200);
            localStorage.setItem('nf_chat', JSON.stringify(toSave));
        },

        clearChat() {
            this.messages = [];
            this.sessionId = crypto.randomUUID();
            localStorage.setItem('nf_session', this.sessionId);
            this.save();
        },

        scrollToBottom() {
            this.$nextTick(() => {
                const el = this.$refs.messages;
                if (el) el.scrollTop = el.scrollHeight;
            });
        },
    };
}
