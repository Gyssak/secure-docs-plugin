<?php
/**
 * Plugin Name: Secure Documents
 * Description: Система тимчасового доступу до документів за спеціальним токеном.
 * Version:     1.0
 * Requires PHP: 8.2
 * Author:      Danyil Kravchuk
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

final class SecureDocuments {

    private const CPT              = 'shared_document';
    private const META_LINK        = '_secure_doc_link';
    private const TOKEN_LIFETIME   = 3600;
    private const NONCE_ACTION     = 'secure_doc_nonce_';
    private const NONCE_FIELD      = 'security';

    public function __construct() {
        add_action('init',             [$this, 'register_cpt']);
        add_action('add_meta_boxes',   [$this, 'add_meta_box']);
        add_action('wp_ajax_generate_secure_link', [$this, 'ajax_generate_link']);
        add_action('template_redirect', [$this, 'handle_access']);
    }

    public function register_cpt(): void {
        register_post_type(self::CPT, [
                'label'  => __('Документи', 'secure-docs'),
                'labels' => [
                        'name'          => __('Документи',           'secure-docs'),
                        'singular_name' => __('Документ',            'secure-docs'),
                        'add_new'       => __('Додати документ',     'secure-docs'),
                        'add_new_item'  => __('Додати новий документ','secure-docs'),
                        'edit_item'     => __('Редагувати документ', 'secure-docs'),
                ],
                'public'             => false,
                'has_archive'        => false,
                'publicly_queryable' => false,
                'show_ui'            => true,
                'show_in_menu'       => true,
                'supports'           => ['title', 'editor'],
                'capability_type'    => 'post',
        ]);
    }


    public function add_meta_box(): void {
        add_meta_box(
                'doc_access',
                __('Управління доступом', 'secure-docs'),
                [$this, 'render_meta_box'],
                self::CPT,
                'side',
                'high'
        );
    }

    public function render_meta_box(WP_Post $post): void {
        $saved_link = (string) get_post_meta($post->ID, self::META_LINK, true);
        $nonce      = wp_create_nonce(self::NONCE_ACTION . $post->ID);
        $placeholder = $saved_link ?: __('Посилання ще не згенеровано', 'secure-docs');
        ?>
        <div style="padding-bottom:10px;">
            <button type="button"
                    id="sd-generate-btn"
                    class="button button-primary"
                    style="width:100%;margin-bottom:10px;"
                    data-post-id="<?php echo esc_attr((string) $post->ID); ?>"
                    data-nonce="<?php echo esc_attr($nonce); ?>">
                <?php esc_html_e('Згенерувати нове посилання', 'secure-docs'); ?>
            </button>

            <label for="sd-secure-link" style="display:block;font-weight:bold;margin-bottom:5px;">
                <?php esc_html_e('Поточне посилання:', 'secure-docs'); ?>
            </label>
            <input type="text"
                   id="sd-secure-link"
                   readonly
                   style="width:100%;padding:5px;background:#f0f0f1;"
                   value="<?php echo esc_attr($placeholder); ?>"
                   onclick="this.select();">
            <p class="description">
                <?php esc_html_e('Посилання дійсне 1 годину з моменту генерації.', 'secure-docs'); ?>
            </p>
        </div>

        <script>
            (function () {
                const btn = document.getElementById('sd-generate-btn');
                if (!btn) return;

                btn.addEventListener('click', async function () {
                    btn.disabled  = true;
                    btn.innerText = '<?php echo esc_js(__('Генерація…', 'secure-docs')); ?>';

                    try {
                        const body = new URLSearchParams({
                            action:   'generate_secure_link',
                            post_id:  btn.dataset.postId,
                            security: btn.dataset.nonce,
                        });

                        const res  = await fetch(ajaxurl, {
                            method:  'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body:    body.toString(),
                        });

                        const json = await res.json();

                        if (json.success) {
                            document.getElementById('sd-secure-link').value = json.data.url;
                        } else {
                            alert('<?php echo esc_js(__('Помилка: ', 'secure-docs')); ?>' + json.data);
                        }
                    } catch (err) {
                        console.error('Secure Documents AJAX error:', err);
                    } finally {
                        btn.disabled  = false;
                        btn.innerText = '<?php echo esc_js(__('Згенерувати нове посилання', 'secure-docs')); ?>';
                    }
                });
            })();
        </script>
        <?php
    }

    public function ajax_generate_link(): void {
        $post_id = isset($_POST['post_id']) ? absint($_POST['post_id']) : 0;

        if (!check_ajax_referer(self::NONCE_ACTION . $post_id, self::NONCE_FIELD, false)) {
            wp_send_json_error(__('Помилка перевірки безпеки.', 'secure-docs'), 403);
        }

        if (!current_user_can('edit_post', $post_id)) {
            wp_send_json_error(__('У вас немає прав на цю дію.', 'secure-docs'), 403);
        }

        $post = get_post($post_id);
        if (!$post || $post->post_type !== self::CPT) {
            wp_send_json_error(__('Документ не знайдено.', 'secure-docs'), 404);
        }

        $expires = time() + self::TOKEN_LIFETIME;
        $token   = $this->generate_token($post_id, $expires);

        $url = add_query_arg([
                'view_doc' => $post_id,
                'token'    => $token,
                'expires'  => $expires,
        ], home_url('/'));

        update_post_meta($post_id, self::META_LINK, esc_url_raw($url));

        wp_send_json_success(['url' => esc_url($url)]);
    }

    public function handle_access(): void {
        if (!isset($_GET['view_doc'])) {
            return;
        }

        $post_id = absint($_GET['view_doc']);
        $token   = sanitize_text_field(wp_unslash($_GET['token']   ?? ''));
        $expires = absint($_GET['expires'] ?? 0);

        if ($expires === 0 || time() > $expires) {
            wp_die(
                    esc_html__('Час дії посилання минув.', 'secure-docs'),
                    esc_html__('Доступ заборонено', 'secure-docs'),
                    ['response' => 403]
            );
        }

        if (!hash_equals($this->generate_token($post_id, $expires), $token)) {
            wp_die(
                    esc_html__('Недійсний токен.', 'secure-docs'),
                    esc_html__('Доступ заборонено', 'secure-docs'),
                    ['response' => 403]
            );
        }

        $post = get_post($post_id);
        if (!$post || $post->post_type !== self::CPT || $post->post_status !== 'publish') {
            wp_die(
                    esc_html__('Документ не знайдено.', 'secure-docs'),
                    esc_html__('Не знайдено', 'secure-docs'),
                    ['response' => 404]
            );
        }

        $this->render_document($post);
        exit;
    }


    private function generate_token(int $post_id, int $expires): string {
        return hash_hmac('sha256', $post_id . '|' . $expires, wp_salt('auth'));
    }

    private function render_document(WP_Post $post): void {
        $title   = esc_html($post->post_title);
        $content = apply_filters('the_content', $post->post_content);
        ?>
        <!DOCTYPE html>
        <html lang="uk">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="robots" content="noindex, nofollow">
            <title><?php echo $title; ?></title>
            <style>
                *, *::before, *::after { box-sizing: border-box; }
                body {
                    font-family: system-ui, -apple-system, sans-serif;
                    max-width: 800px;
                    margin: 40px auto;
                    padding: 0 20px;
                    color: #333;
                    line-height: 1.6;
                }
                h1 {
                    border-bottom: 2px solid #eaeaea;
                    padding-bottom: 10px;
                    margin-bottom: 24px;
                }
                .document-content {
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 8px;
                    border: 1px solid #eaeaea;
                }
                .document-meta {
                    font-size: 0.8rem;
                    color: #999;
                    margin-top: 24px;
                    text-align: right;
                }
            </style>
        </head>
        <body>
        <h1><?php echo $title; ?></h1>
        <div class="document-content">
            <?php echo $content; ?>
        </div>
        <p class="document-meta">
            <?php esc_html_e('Тимчасовий доступ. Посилання недійсне після закінчення терміну.', 'secure-docs'); ?>
        </p>
        </body>
        </html>
        <?php
    }
}

new SecureDocuments();