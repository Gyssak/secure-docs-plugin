<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

class SecureDocuments
{
    public function __construct()
    {
        add_action('init', [$this, 'register_cpt']);
        add_action('add_meta_boxes', [$this, 'add_meta_box']);
        add_action('wp_ajax_generate_secure_link', [$this, 'generate_link']);
        add_action('template_redirect', [$this, 'handle_access']);
    }

    public function register_cpt(): void {
        register_post_type('shared_document', [
            'label' => 'Документи',
            'labels' => [
                'name' => 'Документи',
                'singular_name' => 'Документ',
                'add_new' => 'Додати документ',
                'add_new_item' => 'Додати новий документ',
                'edit_item' => 'Редагувати документ'
            ],
            'public' => false,
            'has_archive' => false,
            'publicly_queryable' => false,
            'show_ui' => true,
            'show_in_menu' => true,
            'supports' => ['title', 'editor']
        ]);
    }

    public function add_meta_box(): void {
        add_meta_box(
            'doc_access',
            'Управління доступом',
            [$this, 'render_meta_box'],
            'shared_document',
            'side',
            'high'
        );
    }

    public function render_meta_box(WP_Post $post): void {
        $saved_link = get_post_meta($post->ID, '_secure_doc_link', true);
        $nonce = wp_create_nonce('secure_doc_nonce_' . $post->ID);
        ?>
        <div style="padding-bottom: 10px;">
            <button type="button" id="generate_link" class="button button-primary" style="width: 100%; margin-bottom: 10px;">
                Згенерувати нове посилання
            </button>

            <label for="secure_link" style="display: block; font-weight: bold; margin-bottom: 5px;">
                Поточне посилання:
            </label>
            <input type="text" id="secure_link" readonly="readonly" style="width:100%; padding: 5px; background: #f0f0f1;"
                   value="<?php echo esc_attr($saved_link ?: 'Посилання ще не згенеровано'); ?>"
                   onclick="this.select();">
            <p class="description">Посилання дійсне 1 годину з моменту генерації.</p>
        </div>

        <script>
            document.getElementById('generate_link').addEventListener('click', function(e) {
                e.preventDefault();
                const btn = this;
                btn.disabled = true;
                btn.innerText = 'Генерація...';

                const data = new URLSearchParams({
                    action: 'generate_secure_link',
                    post_id: '<?php echo $post->ID; ?>',
                    security: '<?php echo $nonce; ?>'
                });

                fetch(ajaxurl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: data.toString()
                })
                    .then(res => res.json())
                    .then(response => {
                        if(response.success) {
                            document.getElementById('secure_link').value = response.data.url;
                        } else {
                            alert('Помилка: ' + response.data);
                        }
                    })
                    .catch(err => console.error('Помилка AJAX:', err))
                    .finally(() => {
                        btn.disabled = false;
                        btn.innerText = 'Згенерувати нове посилання';
                    });
            });
        </script>
        <?php
    }

    public function generate_link(): void
    {
    }

    public function handle_access(): void
    {
    }
}

new SecureDocuments();